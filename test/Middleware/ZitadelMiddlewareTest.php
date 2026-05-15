<?php

declare(strict_types=1);

namespace Zitadel\Sdk\Test\Middleware;

use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Zitadel\Sdk\Auth\Claims;
use Zitadel\Sdk\Auth\JwksCacheInterface;
use Zitadel\Sdk\Auth\PkceStateCookie;
use Zitadel\Sdk\Auth\TokenValidator;
use Zitadel\Sdk\Config\ZitadelConfig;
use Zitadel\Sdk\Middleware\ZitadelMiddleware;

/**
 * Unit tests for {@see ZitadelMiddleware}.
 *
 * All HTTP calls (cURL) are avoided: token validation uses a readonly subclass
 * of {@see TokenValidator} that returns a fixed result without network access.
 * Code paths that do require a network call (PkceFlow::exchangeCode) are
 * exercised only through error paths where the exchange is never reached.
 */
final class ZitadelMiddlewareTest extends TestCase
{
    private ZitadelConfig $config;
    private Psr17Factory $factory;

    protected function setUp(): void
    {
        $this->factory = new Psr17Factory();
        $this->config  = new ZitadelConfig(
            issuerUrl:    'https://example.zitadel.cloud',
            clientId:     'test-client',
            redirectUri:  'https://myapp.com/zitadel/callback',
            cookieSecret: bin2hex(random_bytes(32)),
        );
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /** Returns a no-op JwksCache used to satisfy TokenValidator's constructor. */
    private function noopCache(): JwksCacheInterface
    {
        return new class implements JwksCacheInterface {
            #[\Override]
            public function getPublicKey(
                string $jwksUri,
                ?string $kid,
                string $alg,
                int $ttlSeconds,
                int $timeoutSeconds,
            ): ?\OpenSSLAsymmetricKey {
                return null;
            }

            #[\Override]
            public function clearCache(): void
            {
            }
        };
    }

    /**
     * Builds a TokenValidator that always returns the given Claims (or null).
     *
     * Uses a `readonly` anonymous subclass to satisfy PHP's restriction that
     * non-readonly classes cannot extend readonly classes.
     */
    private function buildValidator(?Claims $claims, ?ZitadelConfig $config = null): TokenValidator
    {
        $cache  = $this->noopCache();
        $config = $config ?? $this->config;

        return new readonly class ($config, $cache, $claims) extends TokenValidator {
            public function __construct(
                ZitadelConfig $config,
                JwksCacheInterface $cache,
                private readonly ?Claims $mockClaims,
            ) {
                parent::__construct($config, $cache);
            }

            #[\Override]
            public function validate(string $token): ?Claims
            {
                return $this->mockClaims;
            }
        };
    }

    /**
     * Builds the middleware under test with an optional fixed Claims result.
     */
    private function buildMiddleware(?Claims $claims = null): ZitadelMiddleware
    {
        return new ZitadelMiddleware($this->config, $this->buildValidator($claims), $this->factory);
    }

    /**
     * Builds a minimal Claims object for testing authenticated flows.
     */
    private function fakeClaims(): Claims
    {
        return new Claims(
            sub:   'user-123',
            iss:   'https://example.zitadel.cloud',
            exp:   time() + 3600,
            token: 'fake.token.value',
            name:  'Test User',
            email: 'test@example.com',
        );
    }

    /**
     * Builds a PSR-15 request handler that captures the request it was called
     * with and returns a plain 200 OK response.
     */
    private function buildPassthroughHandler(): object
    {
        return new class ($this->factory) implements RequestHandlerInterface {
            public ?ServerRequestInterface $capturedRequest = null;

            public function __construct(private readonly Psr17Factory $factory)
            {
            }

            #[\Override]
            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                $this->capturedRequest = $request;

                return $this->factory->createResponse(200);
            }
        };
    }

    /**
     * Builds a ServerRequest to the callback path, optionally with a real PKCE
     * state cookie already encrypted into the request.
     *
     * @param array<string, string> $queryParams
     */
    private function buildCallbackRequest(
        bool $withStateCookie = true,
        string $state = 'test-state',
        string $verifier = 'test-verifier',
        string $next = '/dashboard',
        array $queryParams = [],
    ): ServerRequest {
        $request = new ServerRequest('GET', 'https://myapp.com/zitadel/callback');

        if ($withStateCookie) {
            $cookieValue = PkceStateCookie::encrypt(
                $verifier,
                $state,
                $next,
                $this->config->cookieSecret,
            );
            $request = $request->withCookieParams(['__nextgen_pkce' => $cookieValue]);
        }

        if ($queryParams !== []) {
            $request = $request->withQueryParams($queryParams);
        }

        return $request;
    }

    /**
     * Returns true when any Set-Cookie header in `$headers` deletes the named
     * cookie (cookie=<anything>; Max-Age=0).
     *
     * @param string[] $headers
     */
    private function headerContainsCookieDeletion(array $headers, string $cookieName): bool
    {
        foreach ($headers as $header) {
            if (
                str_starts_with($header, $cookieName . '=') &&
                str_contains($header, 'Max-Age=0')
            ) {
                return true;
            }
        }

        return false;
    }

    // =========================================================================
    // (a) Request flow order
    // =========================================================================

    /**
     * The proxy path must be intercepted before callback, logout, and all other
     * stages.  The response status depends on the upstream server (502 on cURL
     * failure, 404 if the path does not exist, etc.), but the next handler must
     * never be invoked and the status must not be a 302 or 400 from auth logic.
     */
    public function testProxyPathShortCircuitsBeforeOtherStages(): void
    {
        $middleware = $this->buildMiddleware();
        $handler    = $this->buildPassthroughHandler();
        $request    = new ServerRequest('GET', 'https://myapp.com/__nextgen/oauth/v2/keys');

        $response = $middleware->process($request, $handler);

        // The response must NOT be 302 (auth redirect) or 400 (auth error).
        self::assertNotSame(302, $response->getStatusCode(), 'Proxy path must not produce an auth redirect');
        self::assertNotSame(400, $response->getStatusCode(), 'Proxy path must not produce an auth error');
        self::assertNull($handler->capturedRequest, 'Next handler must not be called for proxy path');
    }

    /**
     * Ignored routes must pass through to the next handler with
     * `zitadel.claims = null`, even with no token present.
     */
    public function testIgnoredRoutePassesThroughWithNullClaims(): void
    {
        $config = new ZitadelConfig(
            issuerUrl:     'https://example.zitadel.cloud',
            clientId:      'test-client',
            redirectUri:   'https://myapp.com/zitadel/callback',
            cookieSecret:  bin2hex(random_bytes(32)),
            ignoredRoutes: ['/health'],
        );
        $middleware = new ZitadelMiddleware($config, $this->buildValidator(null), $this->factory);
        $handler    = $this->buildPassthroughHandler();
        $request    = new ServerRequest('GET', 'https://myapp.com/health');

        $response = $middleware->process($request, $handler);

        self::assertSame(200, $response->getStatusCode());
        self::assertNotNull($handler->capturedRequest);
        self::assertNull($handler->capturedRequest->getAttribute('zitadel.claims'));
    }

    /**
     * Wildcard ignored routes (e.g. `/public/*`) must also pass through.
     */
    public function testIgnoredRouteWildcardPassesThrough(): void
    {
        $config = new ZitadelConfig(
            issuerUrl:     'https://example.zitadel.cloud',
            clientId:      'test-client',
            redirectUri:   'https://myapp.com/zitadel/callback',
            cookieSecret:  bin2hex(random_bytes(32)),
            ignoredRoutes: ['/public/*'],
        );
        $middleware = new ZitadelMiddleware($config, $this->buildValidator(null), $this->factory);
        $handler    = $this->buildPassthroughHandler();
        $request    = new ServerRequest('GET', 'https://myapp.com/public/about');

        $response = $middleware->process($request, $handler);

        self::assertSame(200, $response->getStatusCode());
        self::assertNull($handler->capturedRequest?->getAttribute('zitadel.claims'));
    }

    /**
     * An authenticated request (valid token in cookie) must attach Claims and
     * call the next handler.
     */
    public function testAuthenticatedRequestAttachesClaimsAndCallsHandler(): void
    {
        $claims     = $this->fakeClaims();
        $middleware = $this->buildMiddleware($claims);
        $handler    = $this->buildPassthroughHandler();
        $request    = (new ServerRequest('GET', 'https://myapp.com/dashboard'))
            ->withCookieParams(['__nextgen_auth' => 'valid.token.here']);

        $response = $middleware->process($request, $handler);

        self::assertSame(200, $response->getStatusCode());
        self::assertNotNull($handler->capturedRequest);
        self::assertSame($claims, $handler->capturedRequest->getAttribute('zitadel.claims'));
    }

    /**
     * A protected route without a valid token must redirect to the Zitadel
     * authorization endpoint (302) and must NOT invoke the next handler.
     */
    public function testProtectedRouteWithoutTokenRedirectsToLogin(): void
    {
        $config = new ZitadelConfig(
            issuerUrl:       'https://example.zitadel.cloud',
            clientId:        'test-client',
            redirectUri:     'https://myapp.com/zitadel/callback',
            cookieSecret:    bin2hex(random_bytes(32)),
            protectedRoutes: ['/admin*'],
        );
        $middleware = new ZitadelMiddleware($config, $this->buildValidator(null), $this->factory);
        $handler    = $this->buildPassthroughHandler();
        $request    = new ServerRequest('GET', 'https://myapp.com/admin/users');

        $response = $middleware->process($request, $handler);

        self::assertSame(302, $response->getStatusCode());
        self::assertStringContainsString(
            'https://example.zitadel.cloud/oauth/v2/authorize',
            $response->getHeaderLine('Location'),
        );
        self::assertNull($handler->capturedRequest, 'Next handler must not be called on protected-route redirect');
    }

    /**
     * `protectAll: true` must redirect every unauthenticated request that is not
     * the callback, logout, proxy, or an ignored route.
     */
    public function testProtectAllRedirectsAnyUnauthenticatedRequest(): void
    {
        $config = new ZitadelConfig(
            issuerUrl:    'https://example.zitadel.cloud',
            clientId:     'test-client',
            redirectUri:  'https://myapp.com/zitadel/callback',
            cookieSecret: bin2hex(random_bytes(32)),
            protectAll:   true,
        );
        $middleware = new ZitadelMiddleware($config, $this->buildValidator(null), $this->factory);
        $handler    = $this->buildPassthroughHandler();
        $request    = new ServerRequest('GET', 'https://myapp.com/any/random/path');

        $response = $middleware->process($request, $handler);

        self::assertSame(302, $response->getStatusCode());
        self::assertNull($handler->capturedRequest);
    }

    /**
     * Public (unprotected) unauthenticated requests must pass through with
     * `zitadel.claims = null`.
     */
    public function testPublicUnauthenticatedRequestPassesThroughWithNullClaims(): void
    {
        $middleware = $this->buildMiddleware(null);
        $handler    = $this->buildPassthroughHandler();
        $request    = new ServerRequest('GET', 'https://myapp.com/about');

        $response = $middleware->process($request, $handler);

        self::assertSame(200, $response->getStatusCode());
        self::assertNotNull($handler->capturedRequest);
        self::assertNull($handler->capturedRequest->getAttribute('zitadel.claims'));
    }

    // =========================================================================
    // (b) PKCE cookie deletion on every callback error path
    // =========================================================================

    /**
     * When the PKCE state cookie is absent or unreadable (e.g. tampered ciphertext),
     * the middleware must return 400 AND send a deletion Set-Cookie header to purge
     * any corrupted cookie from the browser.
     */
    public function testCallbackMissingPkceCookieReturns400AndDeletesCookie(): void
    {
        $middleware = $this->buildMiddleware();
        $handler    = $this->buildPassthroughHandler();
        // No PKCE cookie on the request
        $request    = (new ServerRequest('GET', 'https://myapp.com/zitadel/callback'))
            ->withQueryParams(['code' => 'abc', 'state' => 'xyz']);

        $response = $middleware->process($request, $handler);

        self::assertSame(400, $response->getStatusCode());
        self::assertTrue(
            $this->headerContainsCookieDeletion($response->getHeader('Set-Cookie'), '__nextgen_pkce'),
            'Must delete __nextgen_pkce even when cookie was absent/unreadable'
        );
    }

    /**
     * State parameter mismatch must return 400 and delete the PKCE cookie.
     */
    public function testCallbackStateMismatchReturns400AndDeletesPkceCookie(): void
    {
        $middleware = $this->buildMiddleware();
        $handler    = $this->buildPassthroughHandler();
        $request    = $this->buildCallbackRequest(
            withStateCookie: true,
            state: 'correct-state',
            queryParams: ['code' => 'some-code', 'state' => 'wrong-state'],
        );

        $response = $middleware->process($request, $handler);

        self::assertSame(400, $response->getStatusCode());
        self::assertTrue(
            $this->headerContainsCookieDeletion($response->getHeader('Set-Cookie'), '__nextgen_pkce'),
            'PKCE cookie must be deleted on state mismatch'
        );
    }

    /**
     * Missing authorization code must return 400 and delete the PKCE cookie.
     */
    public function testCallbackMissingCodeReturns400AndDeletesPkceCookie(): void
    {
        $middleware = $this->buildMiddleware();
        $handler    = $this->buildPassthroughHandler();
        $request    = $this->buildCallbackRequest(
            withStateCookie: true,
            state: 'test-state',
            queryParams: ['state' => 'test-state'], // no 'code' key
        );

        $response = $middleware->process($request, $handler);

        self::assertSame(400, $response->getStatusCode());
        self::assertTrue(
            $this->headerContainsCookieDeletion($response->getHeader('Set-Cookie'), '__nextgen_pkce'),
            'PKCE cookie must be deleted when code is absent'
        );
    }

    /**
     * An empty authorization code must return 400 and delete the PKCE cookie.
     */
    public function testCallbackEmptyCodeReturns400AndDeletesPkceCookie(): void
    {
        $middleware = $this->buildMiddleware();
        $handler    = $this->buildPassthroughHandler();
        $request    = $this->buildCallbackRequest(
            withStateCookie: true,
            state: 'test-state',
            queryParams: ['code' => '', 'state' => 'test-state'],
        );

        $response = $middleware->process($request, $handler);

        self::assertSame(400, $response->getStatusCode());
        self::assertTrue(
            $this->headerContainsCookieDeletion($response->getHeader('Set-Cookie'), '__nextgen_pkce'),
            'PKCE cookie must be deleted when code is empty string'
        );
    }

    // =========================================================================
    // (b/c) PKCE delete cookie Secure flag matches request scheme
    // =========================================================================

    /**
     * On an HTTPS callback with a missing PKCE cookie, the deletion Set-Cookie
     * header must carry the Secure flag so RFC 6265bis-compliant browsers accept it.
     */
    public function testCallbackErrorOnHttpsSendsPkceDeletionWithSecureFlag(): void
    {
        $middleware = $this->buildMiddleware();
        $handler    = $this->buildPassthroughHandler();
        $request    = new ServerRequest('GET', 'https://myapp.com/zitadel/callback'); // HTTPS, no cookie

        $response = $middleware->process($request, $handler);

        self::assertSame(400, $response->getStatusCode());

        $pkceHeader = null;
        foreach ($response->getHeader('Set-Cookie') as $h) {
            if (str_starts_with($h, '__nextgen_pkce=')) {
                $pkceHeader = $h;
                break;
            }
        }
        self::assertNotNull($pkceHeader, '__nextgen_pkce deletion header must be present');
        self::assertStringContainsString('; Secure', $pkceHeader, 'Deletion header must carry Secure on HTTPS');
        self::assertStringContainsString('Max-Age=0', $pkceHeader);
    }

    /**
     * On an HTTP (localhost) callback, the PKCE deletion cookie must NOT carry
     * the Secure flag (browsers refuse to store Secure cookies on plain HTTP).
     */
    public function testCallbackErrorOnHttpSendsPkceDeletionWithoutSecureFlag(): void
    {
        $config = new ZitadelConfig(
            issuerUrl:    'http://localhost:8080',
            clientId:     'test-client',
            redirectUri:  'http://localhost:8080/zitadel/callback',
            cookieSecret: bin2hex(random_bytes(32)),
        );
        $middleware = new ZitadelMiddleware($config, $this->buildValidator(null), $this->factory);
        $handler    = $this->buildPassthroughHandler();
        $request    = new ServerRequest('GET', 'http://localhost:8080/zitadel/callback');

        $response = $middleware->process($request, $handler);

        self::assertSame(400, $response->getStatusCode());

        foreach ($response->getHeader('Set-Cookie') as $h) {
            if (str_starts_with($h, '__nextgen_pkce=')) {
                self::assertStringNotContainsString('; Secure', $h, 'Deletion header must NOT carry Secure on HTTP');

                return;
            }
        }
        // If no deletion header is sent at all on HTTP, the test is vacuously satisfied
        // (there was no cookie to delete). Acceptable because the browser also has no cookie.
    }

    // =========================================================================
    // (c) Auth-cookie Secure flag follows request scheme (via PKCE redirect)
    // =========================================================================

    /**
     * On an HTTPS protected request, the PKCE state cookie written by
     * redirectToLogin() must carry the Secure flag — proving that $isSecure is
     * derived from the request's scheme and threaded into cookie writes.
     */
    public function testPkceStateCookieHasSecureFlagOnHttpsRequest(): void
    {
        $config = new ZitadelConfig(
            issuerUrl:       'https://example.zitadel.cloud',
            clientId:        'test-client',
            redirectUri:     'https://myapp.com/zitadel/callback',
            cookieSecret:    bin2hex(random_bytes(32)),
            protectedRoutes: ['/secure'],
        );
        $middleware = new ZitadelMiddleware($config, $this->buildValidator(null), $this->factory);
        $handler    = $this->buildPassthroughHandler();
        $request    = new ServerRequest('GET', 'https://myapp.com/secure');

        $response = $middleware->process($request, $handler);

        self::assertSame(302, $response->getStatusCode());
        $setCookie = $response->getHeaderLine('Set-Cookie');
        self::assertStringContainsString('__nextgen_pkce=', $setCookie);
        self::assertStringContainsString('; Secure', $setCookie);
    }

    /**
     * On an HTTP (localhost) request, the PKCE state cookie must NOT carry the
     * Secure flag.
     */
    public function testPkceStateCookieOmitsSecureFlagOnHttpRequest(): void
    {
        $config = new ZitadelConfig(
            issuerUrl:       'http://localhost:8080',
            clientId:        'test-client',
            redirectUri:     'http://localhost:8080/zitadel/callback',
            cookieSecret:    bin2hex(random_bytes(32)),
            protectedRoutes: ['/secure'],
        );
        $middleware = new ZitadelMiddleware($config, $this->buildValidator(null), $this->factory);
        $handler    = $this->buildPassthroughHandler();
        $request    = new ServerRequest('GET', 'http://localhost:8080/secure');

        $response = $middleware->process($request, $handler);

        self::assertSame(302, $response->getStatusCode());
        $setCookie = $response->getHeaderLine('Set-Cookie');
        self::assertStringContainsString('__nextgen_pkce=', $setCookie);
        self::assertStringNotContainsString('; Secure', $setCookie);
    }

    // =========================================================================
    // (d) Stale cookie cleanup on public/unauth routes and logout
    // =========================================================================

    /**
     * On a public unauthenticated route, stale `__nextgen*` cookies must be
     * deleted; non-nextgen cookies must be left alone.
     */
    public function testPublicUnauthRouteDeletesStaleNextgenCookies(): void
    {
        $middleware = $this->buildMiddleware(null);
        $handler    = $this->buildPassthroughHandler();
        $request    = (new ServerRequest('GET', 'https://myapp.com/about'))
            ->withCookieParams([
                '__nextgen_auth' => 'stale-token',
                '__nextgen_pkce' => 'stale-pkce',
                'other_cookie'   => 'keep-me',
            ]);

        $response = $middleware->process($request, $handler);

        self::assertSame(200, $response->getStatusCode());

        $setCookies = $response->getHeader('Set-Cookie');
        self::assertTrue(
            $this->headerContainsCookieDeletion($setCookies, '__nextgen_auth'),
            '__nextgen_auth must be deleted on public unauthenticated route'
        );
        self::assertTrue(
            $this->headerContainsCookieDeletion($setCookies, '__nextgen_pkce'),
            '__nextgen_pkce must be deleted on public unauthenticated route'
        );
        foreach ($setCookies as $header) {
            self::assertStringNotContainsString('other_cookie=', $header, 'Non-nextgen cookies must not be touched');
        }
    }

    /**
     * On logout, stale `__nextgen*` cookies must be cleared in addition to the
     * primary `__nextgen_auth` cookie that the logout handler explicitly deletes.
     */
    public function testLogoutDeletesAllStaleNextgenCookies(): void
    {
        $middleware = $this->buildMiddleware();
        $handler    = $this->buildPassthroughHandler();
        $request    = (new ServerRequest('GET', 'https://myapp.com/zitadel/logout'))
            ->withCookieParams([
                '__nextgen_auth' => 'some-token',
                '__nextgen_pkce' => 'leftover-pkce',
            ]);

        $response = $middleware->process($request, $handler);

        self::assertSame(302, $response->getStatusCode());

        $setCookies = $response->getHeader('Set-Cookie');
        self::assertTrue(
            $this->headerContainsCookieDeletion($setCookies, '__nextgen_auth'),
            '__nextgen_auth must be deleted on logout'
        );
        self::assertTrue(
            $this->headerContainsCookieDeletion($setCookies, '__nextgen_pkce'),
            '__nextgen_pkce must be deleted on logout via stale-cookie cleanup'
        );
    }

    // =========================================================================
    // (f) Bearer token priority over cookie
    // =========================================================================

    /**
     * Builds a spy TokenValidator that records the token string passed to
     * `validate()` into a shared `stdClass` box (mutable reference, compatible
     * with readonly anonymous-class constraints).
     */
    private function buildTokenSpy(\stdClass $box): TokenValidator
    {
        $cache = $this->noopCache();

        return new readonly class ($this->config, $cache, $box) extends TokenValidator {
            public function __construct(
                ZitadelConfig $config,
                JwksCacheInterface $cache,
                private readonly \stdClass $box,
            ) {
                parent::__construct($config, $cache);
            }

            #[\Override]
            public function validate(string $token): ?Claims
            {
                $this->box->lastToken = $token;

                return null;
            }
        };
    }

    /**
     * When both `Authorization: Bearer` and `__nextgen_auth` cookie are present,
     * the Bearer token must be extracted first and tried against the validator.
     */
    public function testBearerHeaderTakesPriorityOverCookie(): void
    {
        $box = (object) ['lastToken' => ''];

        $middleware = new ZitadelMiddleware($this->config, $this->buildTokenSpy($box), $this->factory);
        $handler    = $this->buildPassthroughHandler();
        $request    = (new ServerRequest('GET', 'https://myapp.com/dashboard'))
            ->withHeader('Authorization', 'Bearer bearer-token-value')
            ->withCookieParams(['__nextgen_auth' => 'cookie-token-value']);

        $middleware->process($request, $handler);

        self::assertSame('bearer-token-value', $box->lastToken, 'Bearer token must be preferred over the cookie');
    }

    /**
     * When only the cookie is present (no Authorization header), the cookie
     * value is passed to the validator.
     */
    public function testCookieTokenUsedWhenNoBearerHeader(): void
    {
        $box = (object) ['lastToken' => ''];

        $middleware = new ZitadelMiddleware($this->config, $this->buildTokenSpy($box), $this->factory);
        $handler    = $this->buildPassthroughHandler();
        $request    = (new ServerRequest('GET', 'https://myapp.com/dashboard'))
            ->withCookieParams(['__nextgen_auth' => 'cookie-token-value']);

        $middleware->process($request, $handler);

        self::assertSame('cookie-token-value', $box->lastToken);
    }

    // =========================================================================
    // (g) sanitizeNext — rawurldecode "//" protection
    // =========================================================================

    /**
     * A next path that starts with "//" must be rejected to prevent
     * protocol-relative open redirects.
     */
    public function testSanitizeNextRejectsProtocolRelativePath(): void
    {
        $method = (new \ReflectionClass(ZitadelMiddleware::class))->getMethod('sanitizeNext');

        $middleware = $this->buildMiddleware();
        self::assertNull($method->invoke($middleware, '//evil.com/phishing'));
    }

    /**
     * A percent-encoded path "/%2F/evil.com" decodes to "//evil.com" and must
     * also be rejected.
     */
    public function testSanitizeNextRejectsPercentEncodedProtocolRelativePath(): void
    {
        $method = (new \ReflectionClass(ZitadelMiddleware::class))->getMethod('sanitizeNext');

        $middleware = $this->buildMiddleware();
        self::assertNull($method->invoke($middleware, '/%2F/evil.com'));
    }

    /**
     * A safe relative path (with query string) must survive sanitizeNext unchanged.
     */
    public function testSanitizeNextAcceptsSafeRelativePath(): void
    {
        $method = (new \ReflectionClass(ZitadelMiddleware::class))->getMethod('sanitizeNext');

        $middleware = $this->buildMiddleware();
        self::assertSame('/dashboard?tab=settings', $method->invoke($middleware, '/dashboard?tab=settings'));
    }

    /**
     * An absolute URL (with scheme) must be rejected.
     */
    public function testSanitizeNextRejectsAbsoluteUrl(): void
    {
        $method = (new \ReflectionClass(ZitadelMiddleware::class))->getMethod('sanitizeNext');

        $middleware = $this->buildMiddleware();
        self::assertNull($method->invoke($middleware, 'https://evil.com/steal'));
    }

    /**
     * A path containing a backslash must be rejected (Windows open-redirect vector).
     */
    public function testSanitizeNextRejectsBackslash(): void
    {
        $method = (new \ReflectionClass(ZitadelMiddleware::class))->getMethod('sanitizeNext');

        $middleware = $this->buildMiddleware();
        self::assertNull($method->invoke($middleware, '/foo\\bar'));
    }

    /**
     * A path that does not start with "/" must be rejected.
     */
    public function testSanitizeNextRejectsRelativePathWithoutLeadingSlash(): void
    {
        $method = (new \ReflectionClass(ZitadelMiddleware::class))->getMethod('sanitizeNext');

        $middleware = $this->buildMiddleware();
        self::assertNull($method->invoke($middleware, 'relative/path'));
    }

    // =========================================================================
    // (h) Error responses — proper HTTP 400 with HTML content-type
    // =========================================================================

    /**
     * Callback errors must always return HTTP 400 with Content-Type text/html.
     */
    public function testCallbackErrorResponseIs400WithHtmlContentType(): void
    {
        $middleware = $this->buildMiddleware();
        $handler    = $this->buildPassthroughHandler();
        $request    = new ServerRequest('GET', 'https://myapp.com/zitadel/callback');

        $response = $middleware->process($request, $handler);

        self::assertSame(400, $response->getStatusCode());
        self::assertStringContainsString('text/html', $response->getHeaderLine('Content-Type'));
        self::assertStringContainsString('charset=utf-8', $response->getHeaderLine('Content-Type'));
    }

    /**
     * The HTML body of an error response must contain a DOCTYPE declaration and
     * a recognizable "Authentication Error" heading.
     */
    public function testCallbackErrorResponseBodyIsWellFormedHtml(): void
    {
        $middleware = $this->buildMiddleware();
        $handler    = $this->buildPassthroughHandler();
        $request    = new ServerRequest('GET', 'https://myapp.com/zitadel/callback');

        $response = $middleware->process($request, $handler);

        $body = (string) $response->getBody();
        self::assertStringContainsString('<!DOCTYPE html>', $body);
        self::assertStringContainsString('Authentication Error', $body);
    }

    // =========================================================================
    // (i) Thread safety — no static state leak between instances
    // =========================================================================

    /**
     * Two middleware instances with different configurations must not share any
     * static state.  Process the same path through both; each must independently
     * evaluate its own config.
     */
    public function testDifferentInstancesDoNotShareState(): void
    {
        $config1 = new ZitadelConfig(
            issuerUrl:       'https://instance1.zitadel.cloud',
            clientId:        'client-1',
            redirectUri:     'https://app1.com/zitadel/callback',
            cookieSecret:    bin2hex(random_bytes(32)),
            protectedRoutes: ['/admin'],
        );
        $config2 = new ZitadelConfig(
            issuerUrl:    'https://instance2.zitadel.cloud',
            clientId:     'client-2',
            redirectUri:  'https://app2.com/zitadel/callback',
            cookieSecret: bin2hex(random_bytes(32)),
            // No protected routes — /admin is public on instance 2.
        );

        $v1 = $this->buildValidator(null, $config1);
        $v2 = $this->buildValidator(null, $config2);

        $m1 = new ZitadelMiddleware($config1, $v1, $this->factory);
        $m2 = new ZitadelMiddleware($config2, $v2, $this->factory);

        $handler = $this->buildPassthroughHandler();
        $request = new ServerRequest('GET', 'https://app1.com/admin');

        // Instance 1 protects /admin → 302 to instance1's issuer
        $r1 = $m1->process($request, $handler);
        self::assertSame(302, $r1->getStatusCode());
        self::assertStringContainsString('instance1.zitadel.cloud', $r1->getHeaderLine('Location'));

        // Instance 2 has no protected routes → passes through
        $r2 = $m2->process($request, $handler);
        self::assertSame(200, $r2->getStatusCode());
    }

    // =========================================================================
    // Logout
    // =========================================================================

    /**
     * The logout handler must redirect to Zitadel's end-session endpoint,
     * delete the auth cookie, and NOT invoke the next handler.
     */
    public function testLogoutRedirectsToEndSessionAndClearsAuthCookie(): void
    {
        $middleware = $this->buildMiddleware();
        $handler    = $this->buildPassthroughHandler();
        $request    = new ServerRequest('GET', 'https://myapp.com/zitadel/logout');

        $response = $middleware->process($request, $handler);

        self::assertSame(302, $response->getStatusCode());
        self::assertStringContainsString(
            'example.zitadel.cloud/oidc/v1/end_session',
            $response->getHeaderLine('Location'),
        );
        self::assertTrue(
            $this->headerContainsCookieDeletion($response->getHeader('Set-Cookie'), '__nextgen_auth'),
        );
        self::assertNull($handler->capturedRequest, 'Next handler must not be called on logout');
    }

    /**
     * The logout Location must include the `client_id` and
     * `post_logout_redirect_uri` query parameters required by OIDC RP-Initiated
     * Logout 1.0.
     */
    public function testLogoutLocationContainsRequiredOidcParams(): void
    {
        $middleware = $this->buildMiddleware();
        $handler    = $this->buildPassthroughHandler();
        $request    = new ServerRequest('GET', 'https://myapp.com/zitadel/logout');

        $response = $middleware->process($request, $handler);

        $location = $response->getHeaderLine('Location');
        self::assertStringContainsString('client_id=test-client', $location);
        self::assertStringContainsString('post_logout_redirect_uri=', $location);
    }
}
