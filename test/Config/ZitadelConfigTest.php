<?php

declare(strict_types=1);

namespace Zitadel\Sdk\Test\Config;

use PHPUnit\Framework\TestCase;
use Zitadel\Sdk\Config\ZitadelConfig;

final class ZitadelConfigTest extends TestCase
{
    // ---------------------------------------------------------------------------
    // Trailing slash on issuerUrl
    // ---------------------------------------------------------------------------

    /**
     * A trailing slash on issuerUrl causes every JWT to be rejected at step 12
     * because the `iss` claim is compared with strict equality and ZITADEL never
     * includes a trailing slash in the tokens it issues.
     *
     * The constructor must throw rather than silently break authentication.
     */
    public function testThrowsForTrailingSlashOnIssuerUrl(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/trailing slash/i');

        new ZitadelConfig(
            issuerUrl:    'https://example.zitadel.cloud/',
            clientId:     'test-client',
            redirectUri:  'https://myapp.com/callback',
            cookieSecret: bin2hex(random_bytes(32)),
        );
    }

    public function testDoesNotThrowForValidIssuerUrl(): void
    {
        $config = new ZitadelConfig(
            issuerUrl:    'https://example.zitadel.cloud',
            clientId:     'test-client',
            redirectUri:  'https://myapp.com/callback',
            cookieSecret: bin2hex(random_bytes(32)),
        );

        self::assertSame('https://example.zitadel.cloud', $config->issuerUrl);
    }

    public function testThrowsForLocalhostIssuerWithTrailingSlash(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/trailing slash/i');

        new ZitadelConfig(
            issuerUrl:    'http://localhost:8080/',
            clientId:     'test-client',
            redirectUri:  'http://localhost:3000/callback',
            cookieSecret: bin2hex(random_bytes(32)),
        );
    }
}
