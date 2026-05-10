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

    public function testExpiredCacheEntryReturnsNullWhenUnreachable(): void
    {
        // Prime the cache with an entry that's already expired (fetchedAt = 0).
        $fakeKey  = openssl_pkey_new(['private_key_bits' => 512, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        self::assertNotFalse($fakeKey);

        // Use the SAME URL that the cache will look up, so the entry is found
        // but treated as expired (fetchedAt=0 is long past the TTL=1 threshold).
        $cacheKey = 'xyz://nowhere/keys:stale-kid';
        $ref      = new \ReflectionProperty(JwksCache::class, 'store');
        $ref->setValue(null, [
            $cacheKey => ['key' => $fakeKey, 'fetchedAt' => 0],
        ]);

        $cache = new JwksCache();
        // TTL=1 but fetchedAt=0 means the entry expired long ago.
        // The cache will attempt a re-fetch; the invalid URL returns null.
        // Use an invalid scheme so curl fails instantly without a TCP connection.
        // 'xyz://' is not a scheme curl supports — CURLE_UNSUPPORTED_PROTOCOL
        // is returned immediately with no TCP connection attempted.
        $result = $cache->getPublicKey('xyz://nowhere/keys', 'stale-kid', 'RS256', 1, 1);

        self::assertNull($result);
    }
}
