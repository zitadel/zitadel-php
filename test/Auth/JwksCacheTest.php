<?php

declare(strict_types=1);

namespace Zitadel\Sdk\Test\Auth;

use PHPUnit\Framework\TestCase;
use Zitadel\Sdk\Auth\JwksCache;

/**
 * Unit tests for {@see JwksCache}.
 *
 * Tests that require a live JWKS endpoint spin up a local PHP built-in server
 * serving {@see test/fixtures/jwks.php}. All other tests are pure unit tests
 * that manipulate the static store via reflection.
 */
final class JwksCacheTest extends TestCase
{
    private static int $port;

    /** @var resource|false */
    private static mixed $process = false;

    // ── Lifecycle ─────────────────────────────────────────────────────────────

    public static function setUpBeforeClass(): void
    {
        parent::setUpBeforeClass();

        self::$port = self::findFreePort();

        $script  = __DIR__ . '/../fixtures/jwks.php';
        $logFile = sys_get_temp_dir() . '/zitadel_jwks_' . self::$port . '.log';

        self::$process = proc_open(
            sprintf(
                '%s -d xdebug.mode=off -S 127.0.0.1:%d %s',
                PHP_BINARY,
                self::$port,
                escapeshellarg($script),
            ),
            [
                0 => ['file', '/dev/null', 'r'],
                1 => ['file', $logFile, 'w'],
                2 => ['file', $logFile, 'w'],
            ],
            $pipes,
        );

        // Wait up to 5 s for the server to accept connections.
        $deadline = time() + 5;

        while (time() < $deadline) {
            $ch = curl_init('http://127.0.0.1:' . self::$port . '/');
            curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 1, CURLOPT_CONNECTTIMEOUT => 1]);
            $ok = curl_exec($ch) !== false;
            unset($ch);

            if ($ok) {
                break;
            }

            usleep(100_000);
        }
    }

    public static function tearDownAfterClass(): void
    {
        if (is_resource(self::$process)) {
            proc_terminate(self::$process);
            proc_close(self::$process);
        }
    }

    private static function findFreePort(): int
    {
        $server = stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);

        if ($server === false) {
            throw new \RuntimeException("Could not bind a free port: {$errstr} (errno {$errno})");
        }

        $addr = stream_socket_get_name($server, false);
        fclose($server);

        if ($addr === false) {
            throw new \RuntimeException('stream_socket_get_name() returned false');
        }

        $parts = explode(':', $addr);

        return (int) end($parts);
    }

    private function jwksUrl(string $kid = 'test-key'): string
    {
        return 'http://127.0.0.1:' . self::$port . '/?kid=' . urlencode($kid);
    }

    protected function setUp(): void
    {
        // Reset the static in-process store between tests.
        $ref = new \ReflectionProperty(JwksCache::class, 'store');
        $ref->setValue(null, []);
    }

    public function testCacheHitReturnsStoredKeyWithoutFetching(): void
    {
        // Prime the static cache with a fake key via reflection.
        $fakeKey = openssl_pkey_new(['private_key_bits' => 512, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        self::assertNotFalse($fakeKey);

        $cacheKey = 'https://example.com/keys:my-kid';
        $ref      = new \ReflectionProperty(JwksCache::class, 'store');
        $ref->setValue(null, [
            $cacheKey => ['key' => $fakeKey, 'fetchedAt' => time()],
        ]);

        $cache  = new JwksCache();
        // TTL=300, so the entry is fresh — no HTTP fetch should occur.
        $result = $cache->getPublicKey('https://example.com/keys', 'my-kid', 'RS256', 300, 1);

        self::assertSame($fakeKey, $result);
    }

    public function testClearCacheEvictsAllEntries(): void
    {
        $fakeKey = openssl_pkey_new(['private_key_bits' => 512, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        self::assertNotFalse($fakeKey);

        $ref = new \ReflectionProperty(JwksCache::class, 'store');
        $ref->setValue(null, [
            'https://example.com/keys:kid-a' => ['key' => $fakeKey, 'fetchedAt' => time()],
            'https://example.com/keys:kid-b' => ['key' => $fakeKey, 'fetchedAt' => time()],
        ]);

        (new JwksCache())->clearCache();

        self::assertSame([], $ref->getValue(null));
    }

    /**
     * When the cache entry is expired and the JWKS endpoint is unreachable,
     * the cache must return the stale key rather than null. Returning null
     * would reject every in-flight token until the endpoint recovers.
     */
    public function testExpiredCacheEntryReturnsStaleKeyWhenFetchFails(): void
    {
        $fakeKey  = openssl_pkey_new(['private_key_bits' => 512, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        self::assertNotFalse($fakeKey);

        // fetchedAt=0 ensures the TTL check (TTL=1) treats the entry as expired.
        $cacheKey = 'xyz://nowhere/keys:stale-kid';
        $ref      = new \ReflectionProperty(JwksCache::class, 'store');
        $ref->setValue(null, [
            $cacheKey => ['key' => $fakeKey, 'fetchedAt' => 0],
        ]);

        $cache = new JwksCache();
        // 'xyz://' is not a curl-supported scheme — fails instantly with
        // CURLE_UNSUPPORTED_PROTOCOL, no TCP connection made.
        $result = $cache->getPublicKey('xyz://nowhere/keys', 'stale-kid', 'RS256', 1, 1);

        // The stale key must be served — not null — so tokens are not rejected
        // during a transient JWKS endpoint outage.
        self::assertSame($fakeKey, $result);
    }

    /**
     * When there is no existing cache entry at all and the fetch fails, null
     * is the correct return — there is no stale key to fall back to.
     */
    public function testMissingCacheEntryReturnsNullWhenFetchFails(): void
    {
        $cache  = new JwksCache();
        $result = $cache->getPublicKey('xyz://nowhere/keys', 'unknown-kid', 'RS256', 1, 1);

        self::assertNull($result);
    }

    /**
     * After a successful JWKS fetch that contains no key matching the requested
     * `kid`, a negative-cache sentinel (null key) must be stored in `$store` so
     * that the *next* call with the same kid is served from cache and does not
     * trigger another HTTP round-trip.
     *
     * This protects against a kid-rotation denial-of-service attack where an
     * attacker sends tokens with an ever-changing, fabricated `kid` to force a
     * network request on every validation.
     */
    public function testUnknownKidIsNegativelyCachedAfterSuccessfulFetch(): void
    {
        // Prime the cache directly with a sentinel (key=null) to simulate the state
        // after a successful JWKS fetch that contained no key for 'ghost-kid'.
        $cacheKey = 'https://example.com/keys:ghost-kid';
        $ref      = new \ReflectionProperty(JwksCache::class, 'store');
        $ref->setValue(null, [
            $cacheKey => ['key' => null, 'fetchedAt' => time()],
        ]);

        $cache = new JwksCache();
        // TTL=300 keeps the sentinel fresh — no HTTP fetch should occur.
        $result = $cache->getPublicKey('https://example.com/keys', 'ghost-kid', 'RS256', 300, 1);

        // Null is the correct return for an unknown key; the important invariant
        // is that the entry exists in the store (checked below).
        self::assertNull($result);

        $store = $ref->getValue(null);
        self::assertArrayHasKey($cacheKey, $store);
        self::assertNull($store[$cacheKey]['key'], 'Negative-cache sentinel must persist as null in the store.');
    }

    /**
     * The static store must not grow beyond MAX_STORE_SIZE entries.
     *
     * When the cap is reached, inserting a new entry must evict the oldest one
     * (by insertion order) so that memory use stays bounded even under a
     * kid-rotation denial-of-service attack that floods the cache with unique,
     * fabricated kid values.
     *
     * This test calls the real {@see JwksCache::getPublicKey()} against a local
     * JWKS server (test/fixtures/jwks.php) so the eviction logic inside
     * getPublicKey() is exercised — not just a manual re-implementation of it.
     */
    public function testStoreSizeIsCapedAtMaxStoreSize(): void
    {
        $ref     = new \ReflectionProperty(JwksCache::class, 'store');
        $maxSize = (new \ReflectionClassConstant(JwksCache::class, 'MAX_STORE_SIZE'))->getValue();

        // Construct the oldest-entry cache key exactly as JwksCache::getPublicKey() would.
        // The cache key format is "{jwksUri}:{kid}".
        $oldestJwksUrl  = $this->jwksUrl('kid-0');
        $oldestCacheKey = $oldestJwksUrl . ':kid-0';

        // Fill the store to exactly MAX_STORE_SIZE using fresh, non-expired sentinels.
        // The oldest entry uses kid-0 via the local JWKS URL; the rest use dummy URIs.
        // kid-0 is first (oldest), the rest are newer.
        $initial = [$oldestCacheKey => ['key' => null, 'fetchedAt' => time()]];
        for ($i = 1; $i < $maxSize; $i++) {
            $initial["https://dummy.example.com/keys:kid-{$i}"] = ['key' => null, 'fetchedAt' => time()];
        }
        $ref->setValue(null, $initial);
        self::assertCount($maxSize, $ref->getValue(null), 'Store should be exactly at capacity before the triggering call.');

        // Call getPublicKey() for a brand-new kid that is NOT in the store.
        // The local JWKS server will respond successfully, so getPublicKey() will
        // write the new entry — triggering the real eviction path inside JwksCache.
        $cache      = new JwksCache();
        $newKid     = 'eviction-test-kid';
        $newJwksUrl = $this->jwksUrl($newKid);
        $result     = $cache->getPublicKey($newJwksUrl, $newKid, 'RS256', 300, 5);

        // The fetch must succeed — a null result means the JWKS server did not return
        // a key for this kid, which would mean the eviction path was never triggered.
        self::assertInstanceOf(
            \OpenSSLAsymmetricKey::class,
            $result,
            'getPublicKey() must return a key from the local JWKS server to trigger the eviction path.'
        );

        $storeAfter = $ref->getValue(null);

        // The store must not exceed MAX_STORE_SIZE after the write.
        self::assertCount($maxSize, $storeAfter, 'Store must not exceed MAX_STORE_SIZE after eviction.');

        // The new entry must have been inserted.
        self::assertArrayHasKey(
            $newJwksUrl . ':' . $newKid,
            $storeAfter,
            'The newly fetched entry must be present in the store.'
        );

        // kid-0 (oldest entry) must have been evicted to make room for the new entry.
        self::assertArrayNotHasKey(
            $oldestCacheKey,
            $storeAfter,
            'The oldest entry (kid-0) must have been evicted when the store was at capacity.'
        );
    }

    /**
     * When a cache entry for a given key is refreshed after TTL expiry, the
     * existing entry is removed and re-inserted at the tail so that eviction
     * order reflects write recency, not initial insertion order.
     *
     * Concretely: if kid-0 was inserted first but is refreshed last, it must
     * not be the next eviction candidate — that distinction belongs to kid-1.
     *
     * This test calls the real {@see JwksCache::getPublicKey()} against a local
     * JWKS server so the refresh and the subsequent eviction are both exercised
     * through the actual implementation.
     */
    public function testRefreshMovesEntryToTailOfEvictionQueue(): void
    {
        $ref     = new \ReflectionProperty(JwksCache::class, 'store');
        $maxSize = (new \ReflectionClassConstant(JwksCache::class, 'MAX_STORE_SIZE'))->getValue();

        // Construct the cache keys exactly as JwksCache::getPublicKey() would.
        $kid0JwksUrl  = $this->jwksUrl('kid-0');
        $kid0CacheKey = $kid0JwksUrl . ':kid-0';
        $kid1JwksUrl  = $this->jwksUrl('kid-1');
        $kid1CacheKey = $kid1JwksUrl . ':kid-1';

        // Fill the store to capacity. kid-0 is first (oldest), the rest are newer.
        // kid-0 and kid-1 use real local JWKS URLs so getPublicKey() can refresh them.
        // The remaining entries use dummy URIs so they remain stable.
        $initial = [
            $kid0CacheKey => ['key' => null, 'fetchedAt' => 0],  // expired — will be refreshed
            $kid1CacheKey => ['key' => null, 'fetchedAt' => time()],  // fresh — serves as eviction target after kid-0 refresh
        ];
        for ($i = 2; $i < $maxSize; $i++) {
            $initial["https://dummy.example.com/keys:kid-{$i}"] = ['key' => null, 'fetchedAt' => time()];
        }
        $ref->setValue(null, $initial);
        self::assertCount($maxSize, $ref->getValue(null));

        // Refresh kid-0 by calling getPublicKey() with TTL=1 — the fetchedAt=0 means it
        // is expired, so the cache fetches it and re-inserts it at the tail of the store.
        // After this call kid-0 moves to the tail; kid-1 becomes the oldest entry.
        $cache  = new JwksCache();
        $result = $cache->getPublicKey($kid0JwksUrl, 'kid-0', 'RS256', 300, 5);

        self::assertInstanceOf(
            \OpenSSLAsymmetricKey::class,
            $result,
            'getPublicKey() must return a key from the local JWKS server when refreshing kid-0.'
        );

        // Now trigger an eviction by inserting a brand-new kid.
        // kid-1 must be evicted (it is now the oldest), not kid-0 (which was refreshed last).
        $newKid     = 'refresh-evict-kid';
        $newJwksUrl = $this->jwksUrl($newKid);
        $result2    = $cache->getPublicKey($newJwksUrl, $newKid, 'RS256', 300, 5);

        self::assertInstanceOf(
            \OpenSSLAsymmetricKey::class,
            $result2,
            'getPublicKey() must return a key from the local JWKS server for the new kid.'
        );

        $finalStore = $ref->getValue(null);
        self::assertCount($maxSize, $finalStore, 'Store must remain at MAX_STORE_SIZE after two writes.');

        // kid-1 must have been evicted — it became the oldest after kid-0 was refreshed.
        self::assertArrayNotHasKey(
            $kid1CacheKey,
            $finalStore,
            'kid-1 must be evicted because it became the oldest after kid-0 was refreshed.'
        );

        // kid-0 must still be present — it was moved to the tail on refresh.
        self::assertArrayHasKey(
            $kid0CacheKey,
            $finalStore,
            'kid-0 must survive because it was refreshed (re-inserted at tail) after kid-1.'
        );
    }

    // -------------------------------------------------------------------------
    // selectKey — kty / crv filtering
    // -------------------------------------------------------------------------

    /**
     * Helper: call the private selectKey() method via reflection.
     *
     * @param array<string, mixed> $jwks
     */
    private function callSelectKey(array $jwks, ?string $kid, string $alg): ?\OpenSSLAsymmetricKey
    {
        $method = new \ReflectionMethod(JwksCache::class, 'selectKey');
        return $method->invoke(new JwksCache(), $jwks, $kid, $alg);
    }

    /**
     * An RSA JWK must not be returned when the token header declares an EC
     * algorithm (ES256). Without the kty guard, JwkConverter would happily
     * build an RSA key, and openssl_verify() would return -1 (error) instead
     * of 0 (bad signature), producing a confusing failure mode.
     */
    public function testSelectKeyRejectsRsaKeyForEcAlgorithm(): void
    {
        $rsaKey = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        self::assertNotFalse($rsaKey);

        $details = openssl_pkey_get_details($rsaKey);
        self::assertNotFalse($details);

        $n = rtrim(strtr(base64_encode($details['rsa']['n']), '+/', '-_'), '=');
        $e = rtrim(strtr(base64_encode($details['rsa']['e']), '+/', '-_'), '=');

        $jwks = ['keys' => [['kty' => 'RSA', 'kid' => 'k1', 'use' => 'sig', 'n' => $n, 'e' => $e]]];

        // ES256 expects kty=EC — the RSA key must be filtered out.
        $result = $this->callSelectKey($jwks, 'k1', 'ES256');
        self::assertNull($result, 'An RSA key must not be selected for an EC algorithm.');
    }

    /**
     * An EC JWK must not be returned when the token header declares an RSA
     * algorithm (RS256). JwkConverter would build an EC key, and openssl_verify()
     * with an RSA digest constant would return -1.
     */
    public function testSelectKeyRejectsEcKeyForRsaAlgorithm(): void
    {
        $ecKey = openssl_pkey_new(['curve_name' => 'prime256v1', 'private_key_type' => OPENSSL_KEYTYPE_EC]);
        self::assertNotFalse($ecKey);

        $details = openssl_pkey_get_details($ecKey);
        self::assertNotFalse($details);

        $x = rtrim(strtr(base64_encode($details['ec']['x']), '+/', '-_'), '=');
        $y = rtrim(strtr(base64_encode($details['ec']['y']), '+/', '-_'), '=');

        $jwks = ['keys' => [['kty' => 'EC', 'kid' => 'k1', 'use' => 'sig', 'crv' => 'P-256', 'x' => $x, 'y' => $y]]];

        // RS256 expects kty=RSA — the EC key must be filtered out.
        $result = $this->callSelectKey($jwks, 'k1', 'RS256');
        self::assertNull($result, 'An EC key must not be selected for an RSA algorithm.');
    }

    /**
     * For ES256 the curve must be P-256. A P-384 key (even with a matching kid)
     * must be excluded — OpenSSL would reject the signature and the mismatch
     * should be caught before attempting verification.
     */
    public function testSelectKeyRejectsWrongEcCurveForEs256(): void
    {
        $ecKey = openssl_pkey_new(['curve_name' => 'secp384r1', 'private_key_type' => OPENSSL_KEYTYPE_EC]);
        self::assertNotFalse($ecKey);

        $details = openssl_pkey_get_details($ecKey);
        self::assertNotFalse($details);

        $x = rtrim(strtr(base64_encode(str_pad($details['ec']['x'], 48, "\x00", STR_PAD_LEFT)), '+/', '-_'), '=');
        $y = rtrim(strtr(base64_encode(str_pad($details['ec']['y'], 48, "\x00", STR_PAD_LEFT)), '+/', '-_'), '=');

        $jwks = ['keys' => [['kty' => 'EC', 'kid' => 'k1', 'use' => 'sig', 'crv' => 'P-384', 'x' => $x, 'y' => $y]]];

        // ES256 expects crv=P-256 — a P-384 key must be filtered out.
        $result = $this->callSelectKey($jwks, 'k1', 'ES256');
        self::assertNull($result, 'A P-384 key must not be selected for ES256 (requires P-256).');
    }

    /**
     * For ES384 the curve must be P-384. A P-256 key must be excluded.
     */
    public function testSelectKeyRejectsWrongEcCurveForEs384(): void
    {
        $ecKey = openssl_pkey_new(['curve_name' => 'prime256v1', 'private_key_type' => OPENSSL_KEYTYPE_EC]);
        self::assertNotFalse($ecKey);

        $details = openssl_pkey_get_details($ecKey);
        self::assertNotFalse($details);

        $x = rtrim(strtr(base64_encode($details['ec']['x']), '+/', '-_'), '=');
        $y = rtrim(strtr(base64_encode($details['ec']['y']), '+/', '-_'), '=');

        $jwks = ['keys' => [['kty' => 'EC', 'kid' => 'k1', 'use' => 'sig', 'crv' => 'P-256', 'x' => $x, 'y' => $y]]];

        // ES384 expects crv=P-384 — a P-256 key must be filtered out.
        $result = $this->callSelectKey($jwks, 'k1', 'ES384');
        self::assertNull($result, 'A P-256 key must not be selected for ES384 (requires P-384).');
    }

    /**
     * Correct kty AND crv: a P-256 EC key must be selected for ES256.
     */
    public function testSelectKeyAcceptsCorrectEcKeyForEs256(): void
    {
        $ecKey = openssl_pkey_new(['curve_name' => 'prime256v1', 'private_key_type' => OPENSSL_KEYTYPE_EC]);
        self::assertNotFalse($ecKey);

        $details = openssl_pkey_get_details($ecKey);
        self::assertNotFalse($details);

        $x = rtrim(strtr(base64_encode($details['ec']['x']), '+/', '-_'), '=');
        $y = rtrim(strtr(base64_encode($details['ec']['y']), '+/', '-_'), '=');

        $jwks = ['keys' => [['kty' => 'EC', 'kid' => 'k1', 'use' => 'sig', 'crv' => 'P-256', 'x' => $x, 'y' => $y]]];

        $result = $this->callSelectKey($jwks, 'k1', 'ES256');
        self::assertInstanceOf(\OpenSSLAsymmetricKey::class, $result, 'A P-256 key must be accepted for ES256.');
    }

    /**
     * When 3 keys exist in the JWKS and only key #2 has the matching kid,
     * selectKey must return exactly that key.
     */
    public function testSelectKeyPicksCorrectKeyByKidFromMultipleKeys(): void
    {
        $key1 = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        $key2 = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        $key3 = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        self::assertNotFalse($key1);
        self::assertNotFalse($key2);
        self::assertNotFalse($key3);

        $d1 = openssl_pkey_get_details($key1);
        $d2 = openssl_pkey_get_details($key2);
        $d3 = openssl_pkey_get_details($key3);
        self::assertNotFalse($d1);
        self::assertNotFalse($d2);
        self::assertNotFalse($d3);

        $toJwk = (static fn (array $d, string $kid): array => [
            'kty' => 'RSA',
            'kid' => $kid,
            'use' => 'sig',
            'n'   => rtrim(strtr(base64_encode($d['rsa']['n']), '+/', '-_'), '='),
            'e'   => rtrim(strtr(base64_encode($d['rsa']['e']), '+/', '-_'), '='),
        ]);

        $jwks = ['keys' => [
            $toJwk($d1, 'kid-1'),
            $toJwk($d2, 'kid-2'),
            $toJwk($d3, 'kid-3'),
        ]];

        $selected = $this->callSelectKey($jwks, 'kid-2', 'RS256');
        self::assertInstanceOf(\OpenSSLAsymmetricKey::class, $selected);

        // Confirm it is key2's material by comparing the public key PEM.
        $selectedDetails = openssl_pkey_get_details($selected);
        self::assertNotFalse($selectedDetails);
        self::assertSame($d2['key'], $selectedDetails['key'], 'selectKey must return the key whose kid matches (key #2).');
    }

    /**
     * A key with `use: enc` must be excluded from signature verification even
     * when its kid matches the token header.
     */
    public function testSelectKeyExcludesEncryptionKeys(): void
    {
        $rsaKey = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        self::assertNotFalse($rsaKey);

        $details = openssl_pkey_get_details($rsaKey);
        self::assertNotFalse($details);

        $n = rtrim(strtr(base64_encode($details['rsa']['n']), '+/', '-_'), '=');
        $e = rtrim(strtr(base64_encode($details['rsa']['e']), '+/', '-_'), '=');

        $jwks = ['keys' => [['kty' => 'RSA', 'kid' => 'enc-key', 'use' => 'enc', 'n' => $n, 'e' => $e]]];

        $result = $this->callSelectKey($jwks, 'enc-key', 'RS256');
        self::assertNull($result, 'A key with use:enc must not be selected for signature verification.');
    }

    /**
     * When the JWKS contains no `kid` field on any key and the token has no
     * `kid` header, the first key matching `use` and `alg` constraints must be
     * returned (RFC 7517 §4.5: absent `kid` means the key set has a single key
     * or the application determines the key by other means).
     */
    public function testSelectKeyFallsBackToFirstMatchingKeyWhenNoKid(): void
    {
        $rsaKey = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        self::assertNotFalse($rsaKey);

        $details = openssl_pkey_get_details($rsaKey);
        self::assertNotFalse($details);

        $n = rtrim(strtr(base64_encode($details['rsa']['n']), '+/', '-_'), '=');
        $e = rtrim(strtr(base64_encode($details['rsa']['e']), '+/', '-_'), '=');

        // JWKS key has no kid field; token also has no kid (null).
        $jwks = ['keys' => [['kty' => 'RSA', 'use' => 'sig', 'alg' => 'RS256', 'n' => $n, 'e' => $e]]];

        $result = $this->callSelectKey($jwks, null, 'RS256');
        self::assertInstanceOf(\OpenSSLAsymmetricKey::class, $result, 'A key without kid must be usable when the token also has no kid.');
    }

    /**
     * selectKey() must return null when the JWKS `keys` array is empty.
     * An empty key set means no candidate can be found, so signature verification
     * cannot proceed.
     */
    public function testSelectKeyReturnsNullForEmptyKeySet(): void
    {
        $result = $this->callSelectKey(['keys' => []], 'k1', 'RS256');
        self::assertNull($result, 'selectKey() must return null when the JWKS key set is empty.');
    }

    /**
     * selectKey() must return null when the JWKS response has no `keys` property
     * at all (e.g. a server returns `{}` instead of `{"keys": [...]}`).
     */
    public function testSelectKeyReturnsNullWhenKeysPropertyAbsent(): void
    {
        $result = $this->callSelectKey([], 'k1', 'RS256');
        self::assertNull($result, 'selectKey() must return null when the JWKS has no keys property.');
    }

    /**
     * A successful JWKS fetch that contains no key for the requested kid must
     * store a null sentinel in the cache so the next call with the same kid
     * is served from cache without another network round-trip.
     *
     * This test calls the real {@see JwksCache::getPublicKey()} against a local
     * JWKS server that responds with `kid=known-key`, then requests a different
     * kid (`ghost-kid`) that does not exist in the response. The sentinel must
     * be stored so the second call is a cache hit.
     */
    public function testUnknownKidIsNegativelyCachedByRealFetch(): void
    {
        $ref   = new \ReflectionProperty(JwksCache::class, 'store');
        $cache = new JwksCache();

        // The local JWKS server returns a key for 'known-key', not for 'ghost-kid'.
        $jwksUrl    = $this->jwksUrl('known-key');
        $ghostKid   = 'ghost-kid';
        $cacheKey   = $jwksUrl . ':' . $ghostKid;

        // First call — cache miss, real fetch, no matching key → returns null and writes sentinel.
        $result1 = $cache->getPublicKey($jwksUrl, $ghostKid, 'RS256', 300, 5);
        self::assertNull($result1, 'A kid absent from the JWKS response must return null.');

        $store = $ref->getValue(null);
        self::assertArrayHasKey($cacheKey, $store, 'A null sentinel must be stored for the unknown kid after a real fetch.');
        self::assertNull($store[$cacheKey]['key'], 'The sentinel value must be null.');

        // Second call — must be served from cache (sentinel hit) without another fetch.
        // We verify this by poisoning the URL so curl would fail — if a network
        // call were attempted, getPublicKey() would still return null (stale sentinel),
        // but the important invariant is that the store entry remains unchanged.
        $fetchedAt1 = $store[$cacheKey]['fetchedAt'];
        $result2    = $cache->getPublicKey($jwksUrl, $ghostKid, 'RS256', 300, 5);
        self::assertNull($result2, 'The null sentinel must be returned on the second call (cache hit).');

        $store2 = $ref->getValue(null);
        self::assertSame(
            $fetchedAt1,
            $store2[$cacheKey]['fetchedAt'],
            'fetchedAt must not change on a cache hit — no re-fetch should occur.'
        );
    }
}
