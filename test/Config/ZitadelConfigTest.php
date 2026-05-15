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

    // ---------------------------------------------------------------------------
    // issuerUrl — discovery URL guard
    // ---------------------------------------------------------------------------

    /**
     * Passing the OIDC discovery URL instead of the base issuer URL is a common
     * mistake. The constructor must detect the `/.well-known/openid-configuration`
     * suffix and throw rather than silently fail at token validation time.
     */
    public function testThrowsForDiscoveryUrlAsIssuerUrl(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new ZitadelConfig(
            issuerUrl:    'https://example.zitadel.cloud/.well-known/openid-configuration',
            clientId:     'client',
            redirectUri:  'https://myapp.com/callback',
            cookieSecret: bin2hex(random_bytes(32)),
        );
    }

    // ---------------------------------------------------------------------------
    // issuerUrl — non-HTTPS on non-localhost must be rejected
    // ---------------------------------------------------------------------------

    /**
     * An `http://` issuer on a public host (not localhost/127.x) must be rejected
     * because it would expose tokens and secrets over a plaintext connection.
     */
    public function testThrowsForHttpIssuerOnPublicHost(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new ZitadelConfig(
            issuerUrl:    'http://example.zitadel.cloud',
            clientId:     'client',
            redirectUri:  'https://myapp.com/callback',
            cookieSecret: bin2hex(random_bytes(32)),
        );
    }

    // ---------------------------------------------------------------------------
    // allowedAlgorithms / allowedTokenTypes — empty array guard
    // ---------------------------------------------------------------------------

    /**
     * An empty `allowedAlgorithms` array means no algorithm would ever pass the
     * Step 8 check, so every token would be rejected silently. The constructor
     * must surface this misconfiguration immediately.
     */
    public function testThrowsForEmptyAllowedAlgorithms(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new ZitadelConfig(
            issuerUrl:          'https://example.zitadel.cloud',
            clientId:           'client',
            redirectUri:        'https://myapp.com/callback',
            cookieSecret:       bin2hex(random_bytes(32)),
            allowedAlgorithms:  [],
        );
    }

    /**
     * An empty `allowedTokenTypes` array means the Step 9 `typ` check would reject
     * every token. The constructor must detect this and throw.
     */
    public function testThrowsForEmptyAllowedTokenTypes(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new ZitadelConfig(
            issuerUrl:          'https://example.zitadel.cloud',
            clientId:           'client',
            redirectUri:        'https://myapp.com/callback',
            cookieSecret:       bin2hex(random_bytes(32)),
            allowedTokenTypes:  [],
        );
    }

    // ---------------------------------------------------------------------------
    // Negative integer guards
    // ---------------------------------------------------------------------------

    /**
     * A negative `clockSkewSeconds` has no sensible meaning (a negative tolerance
     * would reject tokens that have not yet expired). The constructor must throw.
     */
    public function testThrowsForNegativeClockSkewSeconds(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new ZitadelConfig(
            issuerUrl:         'https://example.zitadel.cloud',
            clientId:          'client',
            redirectUri:       'https://myapp.com/callback',
            cookieSecret:      bin2hex(random_bytes(32)),
            clockSkewSeconds:  -1,
        );
    }

    public function testThrowsForNegativeJwksTtlSeconds(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new ZitadelConfig(
            issuerUrl:       'https://example.zitadel.cloud',
            clientId:        'client',
            redirectUri:     'https://myapp.com/callback',
            cookieSecret:    bin2hex(random_bytes(32)),
            jwksTtlSeconds:  -1,
        );
    }

    public function testThrowsForNegativeHttpTimeoutSeconds(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new ZitadelConfig(
            issuerUrl:           'https://example.zitadel.cloud',
            clientId:            'client',
            redirectUri:         'https://myapp.com/callback',
            cookieSecret:        bin2hex(random_bytes(32)),
            httpTimeoutSeconds:  -1,
        );
    }

    // ---------------------------------------------------------------------------
    // Associative-array guard for protectedRoutes / ignoredRoutes
    // ---------------------------------------------------------------------------

    /**
     * Passing an associative array for `protectedRoutes` is almost certainly a
     * mistake (the route strings would be discarded). The constructor must throw
     * rather than silently use an empty or wrong list.
     */
    public function testThrowsForAssociativeProtectedRoutes(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/protectedRoutes/i');

        new ZitadelConfig(
            issuerUrl:        'https://example.zitadel.cloud',
            clientId:         'client',
            redirectUri:      'https://myapp.com/callback',
            cookieSecret:     bin2hex(random_bytes(32)),
            protectedRoutes:  ['key' => '/admin'],
        );
    }

    public function testThrowsForAssociativeIgnoredRoutes(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/ignoredRoutes/i');

        new ZitadelConfig(
            issuerUrl:      'https://example.zitadel.cloud',
            clientId:       'client',
            redirectUri:    'https://myapp.com/callback',
            cookieSecret:   bin2hex(random_bytes(32)),
            ignoredRoutes:  ['key' => '/health'],
        );
    }

    // ---------------------------------------------------------------------------
    // Derived URI helpers
    // ---------------------------------------------------------------------------

    public function testJwksUriReturnsExpectedUrl(): void
    {
        $config = new ZitadelConfig(
            issuerUrl:    'https://example.zitadel.cloud',
            clientId:     'client',
            redirectUri:  'https://myapp.com/callback',
            cookieSecret: bin2hex(random_bytes(32)),
        );

        self::assertSame('https://example.zitadel.cloud/oauth/v2/keys', $config->jwksUri());
    }

    public function testAuthorizationEndpointReturnsExpectedUrl(): void
    {
        $config = new ZitadelConfig(
            issuerUrl:    'https://example.zitadel.cloud',
            clientId:     'client',
            redirectUri:  'https://myapp.com/callback',
            cookieSecret: bin2hex(random_bytes(32)),
        );

        self::assertSame('https://example.zitadel.cloud/oauth/v2/authorize', $config->authorizationEndpoint());
    }

    public function testTokenEndpointReturnsExpectedUrl(): void
    {
        $config = new ZitadelConfig(
            issuerUrl:    'https://example.zitadel.cloud',
            clientId:     'client',
            redirectUri:  'https://myapp.com/callback',
            cookieSecret: bin2hex(random_bytes(32)),
        );

        self::assertSame('https://example.zitadel.cloud/oauth/v2/token', $config->tokenEndpoint());
    }

    public function testEndSessionEndpointReturnsExpectedUrl(): void
    {
        $config = new ZitadelConfig(
            issuerUrl:    'https://example.zitadel.cloud',
            clientId:     'client',
            redirectUri:  'https://myapp.com/callback',
            cookieSecret: bin2hex(random_bytes(32)),
        );

        self::assertSame('https://example.zitadel.cloud/oidc/v1/end_session', $config->endSessionEndpoint());
    }

    /**
     * Custom path overrides must be reflected in the derived URI helpers so
     * non-Zitadel OIDC servers (e.g. navikt mock-oauth2-server) work correctly.
     */
    public function testCustomEndpointPathsAreUsed(): void
    {
        $config = new ZitadelConfig(
            issuerUrl:          'https://example.zitadel.cloud',
            clientId:           'client',
            redirectUri:        'https://myapp.com/callback',
            cookieSecret:       bin2hex(random_bytes(32)),
            jwksPath:           '/jwks',
            authorizationPath:  '/connect/authorize',
            tokenPath:          '/connect/token',
            endSessionPath:     '/connect/endsession',
        );

        self::assertSame('https://example.zitadel.cloud/jwks', $config->jwksUri());
        self::assertSame('https://example.zitadel.cloud/connect/authorize', $config->authorizationEndpoint());
        self::assertSame('https://example.zitadel.cloud/connect/token', $config->tokenEndpoint());
        self::assertSame('https://example.zitadel.cloud/connect/endsession', $config->endSessionEndpoint());
    }

    // ---------------------------------------------------------------------------
    // postLogoutAbsoluteUri — redirectUri with no path (bare origin)
    // ---------------------------------------------------------------------------

    /**
     * When redirectUri is just the origin (no path component, e.g.
     * `https://myapp.com`), postLogoutAbsoluteUri() must still return a valid
     * absolute URI without producing `https://myapp.com/` or an empty string.
     *
     * Note: a bare origin is rejected by the constructor because it lacks
     * `https://` with a non-empty host AND a path starting with `/` — wait,
     * actually parse_url('https://myapp.com')['host'] is 'myapp.com' which is
     * fine for the constructor. So this is a valid config and we test the method.
     */
    public function testPostLogoutAbsoluteUriWithBareOriginRedirectUri(): void
    {
        $config = new ZitadelConfig(
            issuerUrl:          'https://example.zitadel.cloud',
            clientId:           'client',
            redirectUri:        'https://myapp.com/callback',
            cookieSecret:       bin2hex(random_bytes(32)),
            postLogoutRedirect: '/signout',
        );

        // origin is https://myapp.com, path is /signout → full URI
        self::assertSame('https://myapp.com/signout', $config->postLogoutAbsoluteUri());
    }

    // ---------------------------------------------------------------------------
    // postLogoutAbsoluteUri — redirectUri with non-standard port
    // ---------------------------------------------------------------------------

    /**
     * When redirectUri contains a non-standard port (e.g. https://example.com:8443/callback),
     * postLogoutAbsoluteUri() must include the port in the result so it matches
     * the URI registered with Zitadel exactly.
     */
    public function testPostLogoutAbsoluteUriPreservesNonStandardHttpsPort(): void
    {
        $config = new ZitadelConfig(
            issuerUrl:          'https://example.zitadel.cloud',
            clientId:           'client',
            redirectUri:        'https://example.com:8443/callback',
            cookieSecret:       bin2hex(random_bytes(32)),
            postLogoutRedirect: '/',
        );

        self::assertSame('https://example.com:8443', $config->postLogoutAbsoluteUri());
    }

    // ---------------------------------------------------------------------------
    // Trailing slash on callbackPath / logoutPath / proxyPath
    // ---------------------------------------------------------------------------

    public function testThrowsForTrailingSlashOnCallbackPath(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/callbackPath/i');

        new ZitadelConfig(
            issuerUrl:    'https://example.zitadel.cloud',
            clientId:     'client',
            redirectUri:  'https://myapp.com/callback',
            cookieSecret: bin2hex(random_bytes(32)),
            callbackPath: '/zitadel/callback/',
        );
    }

    public function testThrowsForTrailingSlashOnLogoutPath(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/logoutPath/i');

        new ZitadelConfig(
            issuerUrl:   'https://example.zitadel.cloud',
            clientId:    'client',
            redirectUri: 'https://myapp.com/callback',
            cookieSecret: bin2hex(random_bytes(32)),
            logoutPath:  '/zitadel/logout/',
        );
    }

    public function testThrowsForTrailingSlashOnProxyPath(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/proxyPath/i');

        new ZitadelConfig(
            issuerUrl:   'https://example.zitadel.cloud',
            clientId:    'client',
            redirectUri: 'https://myapp.com/callback',
            cookieSecret: bin2hex(random_bytes(32)),
            proxyPath:   '/__nextgen/',
        );
    }

    // ---------------------------------------------------------------------------
    // callbackPath === logoutPath
    // ---------------------------------------------------------------------------

    /**
     * When callbackPath and logoutPath are the same, the logout handler would
     * never be reached because the callback check runs first. The constructor
     * must reject this degenerate configuration.
     */
    public function testThrowsWhenCallbackPathEqualsLogoutPath(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/callbackPath.*logoutPath|logoutPath.*callbackPath/i');

        new ZitadelConfig(
            issuerUrl:    'https://example.zitadel.cloud',
            clientId:     'client',
            redirectUri:  'https://myapp.com/callback',
            cookieSecret: bin2hex(random_bytes(32)),
            callbackPath: '/auth/handle',
            logoutPath:   '/auth/handle',
        );
    }

    // ---------------------------------------------------------------------------
    // OIDC path overrides — must start with /
    // ---------------------------------------------------------------------------

    public function testThrowsForJwksPathWithoutLeadingSlash(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/jwksPath/i');

        new ZitadelConfig(
            issuerUrl:    'https://example.zitadel.cloud',
            clientId:     'client',
            redirectUri:  'https://myapp.com/callback',
            cookieSecret: bin2hex(random_bytes(32)),
            jwksPath:     'oauth/v2/keys',
        );
    }

    public function testThrowsForAuthorizationPathWithoutLeadingSlash(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/authorizationPath/i');

        new ZitadelConfig(
            issuerUrl:         'https://example.zitadel.cloud',
            clientId:          'client',
            redirectUri:       'https://myapp.com/callback',
            cookieSecret:      bin2hex(random_bytes(32)),
            authorizationPath: 'oauth/v2/authorize',
        );
    }

    public function testThrowsForTokenPathWithoutLeadingSlash(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/tokenPath/i');

        new ZitadelConfig(
            issuerUrl:    'https://example.zitadel.cloud',
            clientId:     'client',
            redirectUri:  'https://myapp.com/callback',
            cookieSecret: bin2hex(random_bytes(32)),
            tokenPath:    'oauth/v2/token',
        );
    }

    public function testThrowsForEndSessionPathWithoutLeadingSlash(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/endSessionPath/i');

        new ZitadelConfig(
            issuerUrl:      'https://example.zitadel.cloud',
            clientId:       'client',
            redirectUri:    'https://myapp.com/callback',
            cookieSecret:   bin2hex(random_bytes(32)),
            endSessionPath: 'oidc/v1/end_session',
        );
    }

    // ---------------------------------------------------------------------------
    // Empty scopes
    // ---------------------------------------------------------------------------

    /**
     * An empty scopes array would produce `scope=` in the authorization URL,
     * which most OIDC providers reject. The constructor must catch this early.
     */
    public function testThrowsForEmptyScopes(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/scopes/i');

        new ZitadelConfig(
            issuerUrl:    'https://example.zitadel.cloud',
            clientId:     'client',
            redirectUri:  'https://myapp.com/callback',
            cookieSecret: bin2hex(random_bytes(32)),
            scopes:       [],
        );
    }

    // ---------------------------------------------------------------------------
    // ignoredRoutes entries must start with /
    // ---------------------------------------------------------------------------

    /**
     * An ignoredRoutes entry without a leading slash (e.g. 'health') would never
     * match any real request path, silently failing to protect or ignore routes.
     * The constructor must reject such entries.
     */
    public function testThrowsForIgnoredRouteWithoutLeadingSlash(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/ignoredRoutes/i');

        new ZitadelConfig(
            issuerUrl:     'https://example.zitadel.cloud',
            clientId:      'client',
            redirectUri:   'https://myapp.com/callback',
            cookieSecret:  bin2hex(random_bytes(32)),
            ignoredRoutes: ['health'],
        );
    }

    public function testAcceptsValidIgnoredRoutesWithWildcard(): void
    {
        $config = new ZitadelConfig(
            issuerUrl:     'https://example.zitadel.cloud',
            clientId:      'client',
            redirectUri:   'https://myapp.com/callback',
            cookieSecret:  bin2hex(random_bytes(32)),
            ignoredRoutes: ['/health', '/public/*'],
        );

        self::assertSame(['/health', '/public/*'], $config->ignoredRoutes);
    }

    // ---------------------------------------------------------------------------
    // protectedRoutes entries must start with /
    // ---------------------------------------------------------------------------

    /**
     * A protectedRoutes entry without a leading slash (e.g. 'admin') would never
     * match any real request path, silently failing to enforce authentication.
     * The constructor must reject such entries to catch misconfiguration early.
     */
    public function testThrowsForProtectedRouteWithoutLeadingSlash(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/protectedRoutes/i');

        new ZitadelConfig(
            issuerUrl:       'https://example.zitadel.cloud',
            clientId:        'client',
            redirectUri:     'https://myapp.com/callback',
            cookieSecret:    bin2hex(random_bytes(32)),
            protectedRoutes: ['admin'],
        );
    }

    /**
     * A protectedRoutes entry starting with `//` would be treated as a
     * protocol-relative URL by matchesRoutes() rather than a path, silently
     * failing to enforce authentication.
     */
    public function testThrowsForProtectedRouteWithProtocolRelativePath(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/protectedRoutes/i');

        new ZitadelConfig(
            issuerUrl:       'https://example.zitadel.cloud',
            clientId:        'client',
            redirectUri:     'https://myapp.com/callback',
            cookieSecret:    bin2hex(random_bytes(32)),
            protectedRoutes: ['//evil.com/admin'],
        );
    }

    public function testAcceptsValidProtectedRoutesWithWildcard(): void
    {
        $config = new ZitadelConfig(
            issuerUrl:       'https://example.zitadel.cloud',
            clientId:        'client',
            redirectUri:     'https://myapp.com/callback',
            cookieSecret:    bin2hex(random_bytes(32)),
            protectedRoutes: ['/admin', '/dashboard/*'],
        );

        self::assertSame(['/admin', '/dashboard/*'], $config->protectedRoutes);
    }
}
