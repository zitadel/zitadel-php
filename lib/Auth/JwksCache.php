<?php

declare(strict_types=1);

namespace Zitadel\Sdk\Auth;

/**
 * Process-scoped cache for JWKS public keys.
 *
 * Keys are fetched from the JWKS endpoint on first use and cached in a static
 * array for `$ttlSeconds` seconds. This mirrors the module-level `Map` used in
 * the TypeScript reference implementation (`jwt.ts:261`).
 *
 * This is one of two classes in the library with mutable state (the other is
 * {@see \Zitadel\Sdk\Bridge\CodeIgniter\ZitadelHolder}). Mutation is intentional
 * and confined to `private static array $store` — no instance state is ever modified.
 *
 * **Long-running runtimes** (Swoole, RoadRunner, FrankenPHP): the static cache
 * persists across requests within a worker process. This is intentional for
 * performance. Set `$jwksTtlSeconds` conservatively if key rotation is frequent.
 * The cache is safe to share across requests — keys are read-only once fetched.
 *
 * **Kid-rotation DoS protection**: when a JWKS fetch succeeds but contains no key
 * matching a requested `kid`, a negative-cache sentinel is stored under the same
 * `{uri}:{kid}` key. Subsequent requests carrying the same unknown `kid` are
 * rejected from the in-process cache — without hitting the network — until the TTL
 * expires. This prevents an attacker from exhausting server connections by sending
 * tokens with a high-cardinality stream of fabricated `kid` values.
 *
 * **Bounded memory**: `$store` is capped at {@see JwksCache::MAX_STORE_SIZE} entries.
 * When the cap is reached, the oldest entry (by insertion order) is evicted before
 * a new one is inserted. This limits memory consumption even when an attacker sends
 * tokens with a high-cardinality stream of fabricated `kid` values — each fabricated
 * kid still causes one network round-trip, but the in-process cache cannot grow
 * beyond `MAX_STORE_SIZE` entries.
 */
final class JwksCache implements JwksCacheInterface
{
    /**
     * Maximum number of entries held in {@see JwksCache::$store} at any time.
     *
     * When this limit is reached, the entry that was inserted first (array head)
     * is evicted to make room for the new one. This keeps memory use bounded
     * even under a kid-rotation denial-of-service attack.
     */
    private const MAX_STORE_SIZE = 500;

    /**
     * In-process key store.
     *
     * Keys: `"{jwksUri}:{kid}"` or `"{jwksUri}:__default__"` when no `kid` is present.
     * Values: `['key' => OpenSSLAsymmetricKey|null, 'fetchedAt' => int]`
     *   A null `key` is a **negative-cache sentinel** — the key was not found in the
     *   JWKS response. The entry is still subject to TTL expiry so that a legitimate
     *   key rotation is picked up after `$ttlSeconds`.
     *
     * Insertion order is preserved (PHP arrays are ordered maps), which lets the
     * eviction strategy simply call `array_shift()` to remove the oldest entry.
     *
     * @var array<string, array{key: \OpenSSLAsymmetricKey|null, fetchedAt: int}>
     */
    private static array $store = [];

    /**
     * Returns the public key for a given JWKS URI and key ID.
     *
     * On a cache hit (key present and not yet expired), returns the cached key
     * without making any HTTP request. On a miss, fetches the JWKS endpoint via
     * cURL, parses the response, converts the matching JWK to an OpenSSL key
     * using {@see JwkConverter::toKey()}, stores it, and returns it.
     *
     * @param string      $jwksUri        JWKS endpoint URL from the issuer.
     * @param string|null $kid            Key ID from the JWT header; null when absent.
     * @param string      $alg            Algorithm from the JWT header — used to filter
     *                                    the JWK set when no `kid` is present.
     * @param int         $ttlSeconds     Cache TTL in seconds.
     * @param int         $timeoutSeconds cURL timeout in seconds.
     * @return \OpenSSLAsymmetricKey|null Null when no matching key found or unreachable.
     */
    #[\Override]
    public function getPublicKey(
        string $jwksUri,
        ?string $kid,
        string $alg,
        int $ttlSeconds,
        int $timeoutSeconds,
    ): ?\OpenSSLAsymmetricKey {
        $cacheKey = $jwksUri . ':' . ($kid ?? '__default__');
        $now      = time();

        if (
            array_key_exists($cacheKey, self::$store) &&
            ($now - self::$store[$cacheKey]['fetchedAt']) < $ttlSeconds
        ) {
            // Returns null for negative-cache sentinels (unknown kid) as well as
            // for valid keys — callers treat null as "key not found".
            return self::$store[$cacheKey]['key'];
        }

        $jwks = $this->fetchJwks($jwksUri, $timeoutSeconds);
        if ($jwks === null) {
            // Serve the stale cached entry on a transient fetch failure rather than
            // rejecting every token until the JWKS endpoint recovers.
            return array_key_exists($cacheKey, self::$store) ? self::$store[$cacheKey]['key'] : null;
        }

        $key = $this->selectKey($jwks, $kid, $alg);

        // Store the result regardless of whether a matching key was found.
        // A null value here acts as a negative-cache sentinel: subsequent
        // requests with the same unknown kid are rejected from cache without
        // making another HTTP round-trip to the JWKS endpoint, which prevents
        // a kid-rotation denial-of-service attack.
        //
        // Before inserting, remove any existing entry for this key so that a
        // re-insert (TTL refresh) moves it to the tail of the insertion-order
        // queue, keeping the eviction order accurate.
        unset(self::$store[$cacheKey]);

        // Enforce the upper bound: evict the oldest entry (array head) when
        // the store is at capacity. array_shift() removes and returns the first
        // element in insertion order, which is the least-recently-written entry.
        if (count(self::$store) >= self::MAX_STORE_SIZE) {
            array_shift(self::$store);
        }

        self::$store[$cacheKey] = ['key' => $key, 'fetchedAt' => $now];

        return $key;
    }

    /** @return array<string, mixed>|null */
    private function fetchJwks(string $jwksUri, int $timeoutSeconds): ?array
    {
        $ch = curl_init($jwksUri);
        if ($ch === false) {
            return null;
        }

        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER      => true,
            CURLOPT_CONNECTTIMEOUT_MS   => $timeoutSeconds * 1000,
            CURLOPT_TIMEOUT_MS          => $timeoutSeconds * 1000,
            CURLOPT_SSL_VERIFYPEER      => true,
            CURLOPT_SSL_VERIFYHOST      => 2,
            CURLOPT_MAXFILESIZE         => 1_048_576, // 1 MB — JWKS payloads are typically < 10 KB
        ]);

        $body     = curl_exec($ch);
        $errno    = curl_errno($ch);
        $httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);

        if ($errno !== 0 || $body === false || !is_string($body)) {
            return null;
        }

        if ($httpCode !== 200) {
            return null;
        }

        if (!json_validate($body)) {
            return null;
        }

        /** @var array<string, mixed>|null $data */
        $data = json_decode($body, true);

        return is_array($data) ? $data : null;
    }

    /**
     * Evicts all entries from the in-process key store.
     *
     * @inheritDoc
     */
    #[\Override]
    public function clearCache(): void
    {
        self::$store = [];
    }

    /**
     * @param array<string, mixed> $jwks
     */
    private function selectKey(array $jwks, ?string $kid, string $alg): ?\OpenSSLAsymmetricKey
    {
        /** @var array<int, array<string, string>> $keys */
        $keys = $jwks['keys'] ?? [];

        $algorithm = Algorithm::tryFrom($alg);

        $candidates = array_filter($keys, static function (array $k) use ($kid, $alg, $algorithm): bool {
            $useOk = !isset($k['use']) || $k['use'] === 'sig';
            $kidOk = $kid === null || ($k['kid'] ?? null) === $kid;
            $algOk = $kid !== null || !isset($k['alg']) || $k['alg'] === $alg;

            // Verify the JWK key type matches the algorithm family.
            // An RSA key must not be selected for an EC algorithm and vice versa,
            // even when the kid matches — using the wrong key type causes
            // openssl_verify() to return -1 (error) rather than 0 (bad signature),
            // which makes it harder to diagnose and slightly more expensive.
            $ktyOk = $algorithm === null || !isset($k['kty']) || $k['kty'] === $algorithm->expectedKty();

            // For EC algorithms verify the key is on the correct curve.
            // ES256 requires P-256, ES384 requires P-384, ES512 requires P-521.
            // A P-521 key must not be returned for an ES256 token even when the
            // kid matches — OpenSSL would reject the signature with an error.
            $expectedCrv = $algorithm?->expectedCrv();
            $crvOk       = $expectedCrv === null || !isset($k['crv']) || $k['crv'] === $expectedCrv;

            return $useOk && $kidOk && $algOk && $ktyOk && $crvOk;
        });

        foreach ($candidates as $jwk) {
            try {
                return JwkConverter::toKey($jwk);
            } catch (\InvalidArgumentException) {
                continue;
            }
        }

        return null;
    }
}
