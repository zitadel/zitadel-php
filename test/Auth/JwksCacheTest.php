<?php

declare(strict_types=1);

namespace Zitadel\Sdk\Test\Auth;

use PHPUnit\Framework\TestCase;
use Zitadel\Sdk\Auth\JwksCache;

/**
 * Unit tests for {@see JwksCache} that do not require a live JWKS endpoint.
 *
 * Live HTTP fetch and unreachable-endpoint behaviour are covered by the
 * integration spec suite, which spins up a navikt mock-oauth2-server.
 */
final class JwksCacheTest extends TestCase
{
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
}
