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

    // ---------------------------------------------------------------------------
    // redirectUri validation
    // ---------------------------------------------------------------------------

    /**
     * A bare relative path as redirectUri (e.g. '/callback') has no host, so
     * parse_url() returns no 'host' key. Without a constructor guard,
     * postLogoutAbsoluteUri() would silently produce 'https://' — a broken URI.
     * The constructor must reject it eagerly.
     */
    public function testThrowsForRelativeRedirectUri(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/redirectUri/i');

        new ZitadelConfig(
            issuerUrl:    'https://example.zitadel.cloud',
            clientId:     'client',
            redirectUri:  '/callback',
            cookieSecret: bin2hex(random_bytes(32)),
        );
    }

    public function testThrowsForHttpRedirectUriOnNonLocalhost(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/redirectUri/i');

        new ZitadelConfig(
            issuerUrl:    'https://example.zitadel.cloud',
            clientId:     'client',
            redirectUri:  'http://myapp.com/callback',
            cookieSecret: bin2hex(random_bytes(32)),
        );
    }

    public function testAcceptsHttpLocalhostRedirectUri(): void
    {
        $config = new ZitadelConfig(
            issuerUrl:    'http://localhost:8080',
            clientId:     'client',
            redirectUri:  'http://localhost:3000/callback',
            cookieSecret: bin2hex(random_bytes(32)),
        );

        self::assertSame('http://localhost:3000/callback', $config->redirectUri);
    }

    // ---------------------------------------------------------------------------
    // callbackPath / logoutPath validation
    // ---------------------------------------------------------------------------

    public function testThrowsForAbsoluteCallbackPath(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/callbackPath/i');

        new ZitadelConfig(
            issuerUrl:    'https://example.zitadel.cloud',
            clientId:     'client',
            redirectUri:  'https://myapp.com/callback',
            cookieSecret: bin2hex(random_bytes(32)),
            callbackPath: 'https://evil.com',
        );
    }

    public function testThrowsForProtocolRelativeCallbackPath(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/callbackPath/i');

        new ZitadelConfig(
            issuerUrl:    'https://example.zitadel.cloud',
            clientId:     'client',
            redirectUri:  'https://myapp.com/callback',
            cookieSecret: bin2hex(random_bytes(32)),
            callbackPath: '//evil.com',
        );
    }

    public function testThrowsForAbsoluteLogoutPath(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/logoutPath/i');

        new ZitadelConfig(
            issuerUrl:    'https://example.zitadel.cloud',
            clientId:     'client',
            redirectUri:  'https://myapp.com/callback',
            cookieSecret: bin2hex(random_bytes(32)),
            logoutPath:   'https://evil.com',
        );
    }

    // ---------------------------------------------------------------------------
    // proxyPath validation
    // ---------------------------------------------------------------------------

    public function testDefaultProxyPathIsNextgen(): void
    {
        $config = new ZitadelConfig(
            issuerUrl:    'https://example.zitadel.cloud',
            clientId:     'client',
            redirectUri:  'https://myapp.com/callback',
            cookieSecret: bin2hex(random_bytes(32)),
        );

        self::assertSame('/__nextgen', $config->proxyPath);
    }

    public function testCustomProxyPathIsAccepted(): void
    {
        $config = new ZitadelConfig(
            issuerUrl:    'https://example.zitadel.cloud',
            clientId:     'client',
            redirectUri:  'https://myapp.com/callback',
            cookieSecret: bin2hex(random_bytes(32)),
            proxyPath:    '/auth-proxy',
        );

        self::assertSame('/auth-proxy', $config->proxyPath);
    }

    public function testThrowsForAbsoluteProxyPath(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/proxyPath/i');

        new ZitadelConfig(
            issuerUrl:    'https://example.zitadel.cloud',
            clientId:     'client',
            redirectUri:  'https://myapp.com/callback',
            cookieSecret: bin2hex(random_bytes(32)),
            proxyPath:    'https://evil.com',
        );
    }

    public function testThrowsForProtocolRelativeProxyPath(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/proxyPath/i');

        new ZitadelConfig(
            issuerUrl:    'https://example.zitadel.cloud',
            clientId:     'client',
            redirectUri:  'https://myapp.com/callback',
            cookieSecret: bin2hex(random_bytes(32)),
            proxyPath:    '//evil.com',
        );
    }

    // ---------------------------------------------------------------------------
    // postLogoutAbsoluteUri()
    // ---------------------------------------------------------------------------

    /**
     * When redirectUri uses a non-standard port (e.g. localhost:3000), the port
     * must be preserved in the absolute post-logout URI so it matches the URI
     * that was registered with Zitadel exactly.
     */
    public function testPostLogoutAbsoluteUriIncludesNonStandardPort(): void
    {
        $config = new ZitadelConfig(
            issuerUrl:           'http://localhost:8080',
            clientId:            'client',
            redirectUri:         'http://localhost:3000/zitadel/callback',
            cookieSecret:        bin2hex(random_bytes(32)),
            postLogoutRedirect:  '/',
        );

        self::assertSame('http://localhost:3000', $config->postLogoutAbsoluteUri());
    }

    /**
     * When postLogoutRedirect is '/' (the default), the method must return just
     * the origin (scheme + host [+ port]) without a trailing slash, matching the
     * root URL registered in Zitadel.
     */
    public function testPostLogoutAbsoluteUriWithRootRedirectReturnsOrigin(): void
    {
        $config = new ZitadelConfig(
            issuerUrl:           'https://example.zitadel.cloud',
            clientId:            'client',
            redirectUri:         'https://myapp.com/zitadel/callback',
            cookieSecret:        bin2hex(random_bytes(32)),
            postLogoutRedirect:  '/',
        );

        self::assertSame('https://myapp.com', $config->postLogoutAbsoluteUri());
    }

    /**
     * When postLogoutRedirect is a non-root path (e.g. '/goodbye'), the method
     * must append that path to the origin so callers can rely on a single
     * source of truth for the registered URI.
     */
    public function testPostLogoutAbsoluteUriAppendsNonRootPath(): void
    {
        $config = new ZitadelConfig(
            issuerUrl:           'https://example.zitadel.cloud',
            clientId:            'client',
            redirectUri:         'https://myapp.com/zitadel/callback',
            cookieSecret:        bin2hex(random_bytes(32)),
            postLogoutRedirect:  '/goodbye',
        );

        self::assertSame('https://myapp.com/goodbye', $config->postLogoutAbsoluteUri());
    }
}
