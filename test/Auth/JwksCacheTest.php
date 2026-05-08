<?php

declare(strict_types=1);

namespace Zitadel\Sdk\Test\Auth;

use PHPUnit\Framework\TestCase;
use Zitadel\Sdk\Auth\JwksCache;

/**
 * Tests for {@see JwksCache} that don't require a live JWKS endpoint.
 *
 * Integration-level tests (live JWKS fetch) are in the spec suite.
 */
final class JwksCacheTest extends TestCase
{
    public function testReturnsNullForUnreachableEndpoint(): void
    {
        $cache = new JwksCache();
        $key   = $cache->getPublicKey(
            'https://localhost:1/does-not-exist/keys',
            null,
            'RS256',
            300,
            1,
        );

        self::assertNull($key);
    }

    public function testCacheMissReturnsNull(): void
    {
        // Full JWKS-fetch tests (live HTTP) are in the spec suite.
        // This confirms the cache returns null for a non-existent unreachable endpoint,
        // exercising the cURL failure path.
        $cache = new JwksCache();
        $key   = $cache->getPublicKey(
            'https://0.0.0.0:1/no-such-jwks',
            'any-kid',
            'RS256',
            300,
            1,
        );

        self::assertNull($key);
    }
}
