<?php

declare(strict_types=1);

namespace Zitadel\Sdk\Middleware;

use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Zitadel\Sdk\Attribute\AllowAnonymous;
use Zitadel\Sdk\Auth\HttpProxy;
use Zitadel\Sdk\Auth\PkceFlow;
use Zitadel\Sdk\Auth\PkceStateCookie;
use Zitadel\Sdk\Auth\TokenValidator;
use Zitadel\Sdk\Config\ZitadelConfig;

/**
 * PSR-15 middleware that owns the complete Zitadel authentication lifecycle.
 *
 * No framework routes are required. The middleware intercepts the callback and
 * logout paths before the framework router runs.
 *
 * Processing order per request:
 *
 * 0. **Proxy** (`proxyPath`): strips hop-by-hop and internal headers, forwards the
 *    request to `$issuerUrl`, upgrades `__nextgen*` cookies to `Secure` on HTTPS,
 *    and returns the upstream response verbatim without touching auth state.
 *
 * 1. **Callback** (`callbackPath`): validates PKCE state cookie, asserts `state` param
 *    matches, exchanges authorization code for tokens, validates the access token, sets
 *    the `__nextgen_auth` session cookie, and redirects to the originally requested path.
 *
 * 2. **Logout** (`logoutPath`): deletes the `__nextgen_auth` cookie and redirects to
 *    Zitadel's end-session endpoint with `post_logout_redirect_uri`.
 *
 * 3. **Ignored routes** (`ignoredRoutes`): passes through without token validation.
 *    Supports `prefix*` wildcards.
 *
 * 4. **Token extraction**: prefers `Authorization: Bearer` over the `__nextgen_auth`
 *    session cookie when both are present.
 *
 * 5. **Token validation**: validates via {@see TokenValidator}.
 *
 * 6. **Authenticated**: attaches {@see \Zitadel\Sdk\Auth\Claims} to request attribute
 *    `"zitadel.claims"` and passes to the next handler.
 *
 * 6a. **`#[AllowAnonymous]` check** (when route attributes are present): reflects on the
 *     matched handler; if found, passes through without requiring a session.
 *
 * 7. **Protected route** (`protectedRoutes` or `protectAll: true`): generates PKCE
 *    challenge, stores state in encrypted `__nextgen_pkce` cookie, redirects to Zitadel.
 *
 * 8. **Public route, unauthenticated**: attaches null to `"zitadel.claims"`, deletes
 *    stale `__nextgen*` cookies, passes through.
 */
readonly class ZitadelMiddleware implements MiddlewareInterface
{
    /**
     * Mezzio stores the matched route result under this request attribute key.
     * Extracted as a constant to survive a future Mezzio package rename without
     * a silent runtime breakage that only manifests on protected routes.
     */
    private const string MEZZIO_ROUTE_RESULT = 'Mezzio\Router\RouteResult';

    /**
     * @param ZitadelConfig            $config          Middleware configuration.
     * @param TokenValidator           $validator       JWT validator backed by the JWKS cache.
     * @param ResponseFactoryInterface $responseFactory PSR-17 factory for redirect responses.
     */
    public function __construct(
        private ZitadelConfig            $config,
        private TokenValidator           $validator,
        private ResponseFactoryInterface $responseFactory,
    ) {
    }

    /**
     * Processes an incoming server request and returns a response.
     *
     * Intercepts the full Zitadel authentication lifecycle: callback, logout, ignored
     * routes, token validation, `#[AllowAnonymous]` reflection, protected-route redirect,
     * and stale-cookie cleanup for public unauthenticated requests.
     *
     * @param ServerRequestInterface  $request The incoming PSR-7 server request.
     * @param RequestHandlerInterface $handler The next handler in the PSR-15 pipeline.
     * @return ResponseInterface The HTTP response.
     * @throws \InvalidArgumentException When the cookie secret is invalid (propagated from
     *                                   {@see PkceStateCookie::encrypt()} on protected-route redirect).
     */
    #[\Override]
    public function process(
        ServerRequestInterface  $request,
        RequestHandlerInterface $handler,
    ): ResponseInterface {
        $uri      = $request->getUri();
        $path     = $uri->getPath();
        $isSecure = $uri->getScheme() === 'https';

        // Step 0 — proxy
        if (HttpProxy::isProxyPath($path, $this->config->proxyPath)) {
            return $this->handleProxy($request, $isSecure);
        }

        // Step 1 — callback
        if ($path === $this->config->callbackPath) {
            return $this->handleCallback($request, $isSecure);
        }

        // Step 2 — logout
        if ($path === $this->config->logoutPath) {
            return $this->handleLogout($request, $isSecure);
        }

        // Step 3 — ignored routes
        if (PkceFlow::matchesRoutes($path, $this->config->ignoredRoutes)) {
            return $handler->handle($request->withAttribute('zitadel.claims', null));
        }

        // Steps 4–5 — extract and validate token
        $token  = $this->extractToken($request);
        $claims = $token !== null ? $this->validator->validate($token) : null;

        // Step 6 — authenticated
        if ($claims !== null) {
            return $handler->handle($request->withAttribute('zitadel.claims', $claims));
        }

        // Step 6a — #[AllowAnonymous] check (Mezzio only: RouteResult set by RouteMiddleware)
        if ($this->hasAllowAnonymous($request)) {
            return $handler->handle($request->withAttribute('zitadel.claims', null));
        }

        // Step 7 — protected route redirect
        if ($this->config->protectAll || PkceFlow::matchesRoutes($path, $this->config->protectedRoutes)) {
            return $this->redirectToLogin($request, $isSecure);
        }

        // Step 8 — public unauthenticated
        $response = $handler->handle($request->withAttribute('zitadel.claims', null));

        return $this->deleteStaleNextgenCookies($response, $request, $isSecure);
    }

    /**
     * Reverse-proxies a `/__nextgen/*` request to the upstream auth backend.
     *
     * Strips hop-by-hop and internal headers in both directions, appends
     * `REMOTE_ADDR` to the `X-Forwarded-For` chain, and upgrades `__nextgen*`
     * session cookies to `Secure` when the client connection is HTTPS.
     * Returns a 502 Bad Gateway on cURL failure.
     *
     * @param ServerRequestInterface $request  The incoming proxy request.
     * @param bool                   $isSecure Whether the request was made over HTTPS.
     * @return ResponseInterface The upstream response (or 502 on failure).
     */
    private function handleProxy(ServerRequestInterface $request, bool $isSecure): ResponseInterface
    {
        $uri    = $request->getUri();
        $suffix = substr($uri->getPath(), strlen(rtrim($this->config->proxyPath, '/')));
        $query  = $uri->getQuery();

        // Reject path traversal — a suffix containing '..' could resolve to an
        // unintended path on the issuer server even though the host stays the same.
        if (str_contains($suffix, '..')) {
            $response = $this->responseFactory->createResponse(400);
            $response->getBody()->write('Bad Request');

            return $response->withHeader('Content-Type', 'text/plain; charset=utf-8');
        }

        $target = $this->config->issuerUrl . $suffix . ($query !== '' ? '?' . $query : '');

        $headers = [];
        foreach ($request->getHeaders() as $name => $values) {
            $headers[$name] = implode(', ', $values);
        }

        // Mirror Next.js/Nuxt behavior: consider X-Forwarded-Proto so that session
        // cookies get the Secure flag even when TLS is terminated at a load balancer.
        $cookiesSecure = $isSecure || strtolower($request->getHeaderLine('X-Forwarded-Proto')) === 'https';

        $method     = $request->getMethod();
        $hasBody    = !in_array(strtoupper($method), ['GET', 'HEAD'], true);
        $body       = $hasBody ? (string) $request->getBody() : '';
        $server     = $request->getServerParams();
        $remoteAddr = (string) ($server['REMOTE_ADDR'] ?? '');
        $host       = $request->getHeaderLine('Host') ?: $uri->getHost();
        $proto      = $uri->getScheme();

        try {
            $result = HttpProxy::forward(
                $method,
                $target,
                $headers,
                $body,
                $remoteAddr,
                $host,
                $proto,
                $this->config->httpTimeoutSeconds,
            );
        } catch (\RuntimeException) {
            $response = $this->responseFactory->createResponse(502);
            $response->getBody()->write('Bad Gateway');

            return $response->withHeader('Content-Type', 'text/plain; charset=utf-8');
        }

        $response = $this->responseFactory->createResponse($result['status']);

        foreach ($result['headers'] as $name => $values) {
            foreach ($values as $value) {
                $response = $response->withAddedHeader($name, $value);
            }
        }

        foreach ($result['setCookies'] as $cookie) {
            $response = $response->withAddedHeader(
                'Set-Cookie',
                HttpProxy::upgradeSessionCookie($cookie, $cookiesSecure),
            );
        }

        $response->getBody()->write($result['body']);

        return $response;
    }

    /**
     * Validates the PKCE state cookie, exchanges the authorization code, and redirects
     * to the originally requested path with the session cookie set.
     *
     * @param ServerRequestInterface $request  The callback request.
     * @param bool                   $isSecure Whether the request was made over HTTPS.
     * @return ResponseInterface A 302 redirect on success, or a 400 error response on failure.
     */
    private function handleCallback(ServerRequestInterface $request, bool $isSecure): ResponseInterface
    {
        $pkce = PkceStateCookie::read($request, $this->config->cookieSecret);

        // Delete the PKCE cookie immediately — it is single-use regardless of outcome.
        // Match the Secure flag of the incoming request so browsers that enforce the
        // Secure-cookie deletion rule (RFC 6265bis) will accept the expiry header.
        $pkceDeleteCookie = '__nextgen_pkce=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax'
            . ($isSecure ? '; Secure' : '');

        if ($pkce === null) {
            // The cookie was absent or could not be decrypted (tampered/wrong key).
            // Send the delete header anyway to clear any corrupted cookie from the browser.
            return $this->badRequest('Authentication failed — PKCE state cookie missing or invalid. Please try signing in again.')
                ->withAddedHeader('Set-Cookie', $pkceDeleteCookie);
        }

        $params = $request->getQueryParams();
        $code   = $params['code'] ?? null;
        $state  = $params['state'] ?? null;

        if (!hash_equals($pkce['state'], (string) $state)) {
            return $this->badRequest('Authentication failed — state parameter mismatch. Please try signing in again.')
                ->withAddedHeader('Set-Cookie', $pkceDeleteCookie);
        }

        if (!is_string($code) || $code === '') {
            $oauthError = $params['error_description'] ?? $params['error'] ?? 'Missing code';
            return $this->badRequest("Authentication failed — {$oauthError}. Please try signing in again.")
                ->withAddedHeader('Set-Cookie', $pkceDeleteCookie);
        }

        try {
            $tokens = PkceFlow::exchangeCode($this->config, $code, $pkce['verifier']);
        } catch (\Zitadel\Sdk\Exception\PkceException) {
            return $this->badRequest('Authentication failed — the login server returned an error. Please try signing in again.')
                ->withAddedHeader('Set-Cookie', $pkceDeleteCookie);
        }

        $tokenToValidate = PkceFlow::selectToken($tokens);
        if ($tokenToValidate === null) {
            return $this->badRequest('Authentication failed — no usable token in response.')
                ->withAddedHeader('Set-Cookie', $pkceDeleteCookie);
        }

        $claims = $this->validator->validate($tokenToValidate);
        if ($claims === null) {
            return $this->badRequest('Authentication failed — could not validate the token received from the identity provider.')
                ->withAddedHeader('Set-Cookie', $pkceDeleteCookie);
        }

        // Defence-in-depth: confirm the token contains only base64url + '.' before
        // embedding it in a Set-Cookie header value. TokenValidator already verifies
        // the structure, but an explicit guard here prevents a compromised IdP from
        // injecting CRLF sequences through a crafted token string.
        if (preg_match('/^[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+$/', $tokenToValidate) !== 1) {
            return $this->badRequest('Authentication failed — token contains unsafe characters.')
                ->withAddedHeader('Set-Cookie', $pkceDeleteCookie);
        }

        $maxAge = max(0, $claims->exp - time());
        $secure = $isSecure ? '; Secure' : '';
        $next   = PkceFlow::sanitizeNext($pkce['next']) ?? $this->config->postLoginRedirect;

        return $this->responseFactory->createResponse(302)
            ->withAddedHeader('Set-Cookie', $pkceDeleteCookie)
            ->withAddedHeader('Set-Cookie', "__nextgen_auth={$tokenToValidate}; Max-Age={$maxAge}; Path=/; HttpOnly; SameSite=Lax{$secure}")
            ->withHeader('Location', $next);
    }

    /**
     * Clears the session cookie and redirects to Zitadel's end-session endpoint.
     *
     * @param ServerRequestInterface $request The logout request (used to collect stale cookies).
     * @return ResponseInterface A 302 redirect to the OIDC end-session endpoint.
     */
    private function handleLogout(ServerRequestInterface $request, bool $isSecure): ResponseInterface
    {
        $params = http_build_query([
            'client_id'                => $this->config->clientId,
            'post_logout_redirect_uri' => $this->config->postLogoutAbsoluteUri(),
        ]);

        $secure   = $isSecure ? '; Secure' : '';
        $response = $this->responseFactory->createResponse(302)
            ->withHeader('Location', $this->config->endSessionEndpoint() . '?' . $params)
            ->withAddedHeader('Set-Cookie', "__nextgen_auth=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax{$secure}");

        return $this->deleteStaleNextgenCookies($response, $request, $isSecure);
    }

    /**
     * Generates a PKCE challenge and redirects to the Zitadel authorization endpoint.
     *
     * Stores the verifier, state, and return-to path in an encrypted `__nextgen_pkce` cookie.
     *
     * @param ServerRequestInterface $request  The protected request being redirected.
     * @param bool                   $isSecure Whether the request was made over HTTPS.
     * @return ResponseInterface A 302 redirect to the Zitadel authorization endpoint.
     */
    private function redirectToLogin(ServerRequestInterface $request, bool $isSecure): ResponseInterface
    {
        $uri      = $request->getUri();
        $next     = $uri->getPath();
        $query    = $uri->getQuery();
        if ($query !== '') {
            $next .= '?' . $query;
        }

        $verifier   = PkceFlow::generateCodeVerifier();
        $state      = PkceFlow::generateState();
        $challenge  = PkceFlow::generateCodeChallenge($verifier);
        $authUrl    = PkceFlow::buildAuthorizationUrl($this->config, $challenge, $state);

        $response = $this->responseFactory->createResponse(302)->withHeader('Location', $authUrl);

        return PkceStateCookie::write($response, $verifier, $state, $next, $this->config->cookieSecret, $isSecure, $this->config->pkceCookieTtlSeconds);
    }

    /**
     * Extracts the raw JWT from the request — preferring `Authorization: Bearer` over cookie.
     *
     * @param ServerRequestInterface $request The incoming request.
     * @return string|null The raw token string, or null if neither source is present.
     */
    private function extractToken(ServerRequestInterface $request): ?string
    {
        $authHeader = $request->getHeaderLine('Authorization');
        if (preg_match('/^Bearer\s+(\S+)$/i', $authHeader, $m)) {
            return $m[1];
        }

        $cookies = $request->getCookieParams();
        $cookie  = $cookies['__nextgen_auth'] ?? null;

        return is_string($cookie) && $cookie !== '' ? $cookie : null;
    }

    /**
     * Appends expired `Set-Cookie` directives to delete every `__nextgen*` cookie present
     * in the incoming request.
     *
     * @param ResponseInterface      $response The response to augment.
     * @param ServerRequestInterface $request  The request whose cookies are scanned.
     * @return ResponseInterface The response with stale-cookie deletion headers added.
     */
    private function deleteStaleNextgenCookies(
        ResponseInterface      $response,
        ServerRequestInterface $request,
        bool                   $isSecure = false,
    ): ResponseInterface {
        $secure  = $isSecure ? '; Secure' : '';
        $cookies = $request->getCookieParams();
        foreach (array_keys($cookies) as $name) {
            $name = (string) $name;
            if (!str_starts_with($name, '__nextgen')) {
                continue;
            }

            // Guard against cookie-name injection: only emit a Set-Cookie header
            // for names that consist entirely of safe token characters (RFC 6265 §4.1).
            // A crafted cookie name like "__nextgen=x" would produce a malformed header.
            if (preg_match('/^[A-Za-z0-9_\-]+$/', $name) !== 1) {
                continue;
            }

            $response = $response->withAddedHeader(
                'Set-Cookie',
                "{$name}=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax{$secure}"
            );
        }

        return $response;
    }

    /**
     * Returns true when the matched route handler carries a
     * {@see \Zitadel\Sdk\Attribute\AllowAnonymous} attribute.
     *
     * Inspects the `Mezzio\Router\RouteResult` request attribute set by Mezzio's
     * `RouteMiddleware`. Returns false when the attribute is absent (e.g. when the
     * middleware runs before routing).
     *
     * @param ServerRequestInterface $request The current request.
     * @return bool True if the matched handler permits unauthenticated access.
     */
    private function hasAllowAnonymous(ServerRequestInterface $request): bool
    {
        // RouteResult attribute is set by Mezzio's RouteMiddleware
        $routeResult = $request->getAttribute(self::MEZZIO_ROUTE_RESULT);
        if ($routeResult !== null && method_exists($routeResult, 'getMatchedRoute')) {
            $route = $routeResult->getMatchedRoute();
            if ($route !== null && method_exists($route, 'getOptions')) {
                $handler = $route->getOptions()['middleware'] ?? null;
                if ($handler !== null && $this->classOrMethodHasAttribute($handler)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Returns true when a class string has `#[AllowAnonymous]` on the class itself
     * or on its `__invoke` method.
     *
     * @param mixed $handler The handler to inspect; non-string and non-existent classes return false.
     * @return bool True if the class or its `__invoke` method has the AllowAnonymous attribute.
     */
    private function classOrMethodHasAttribute(mixed $handler): bool
    {
        if (!is_string($handler) || !class_exists($handler)) {
            return false;
        }

        $ref = new \ReflectionClass($handler);
        if (!empty($ref->getAttributes(AllowAnonymous::class))) {
            return true;
        }

        if ($ref->hasMethod('__invoke')) {
            return !empty($ref->getMethod('__invoke')->getAttributes(AllowAnonymous::class));
        }

        return false;
    }

    /**
     * Builds a 400 Bad Request HTML error response with a human-readable message.
     *
     * @param string $message The authentication error description shown to the user.
     * @return ResponseInterface A 400 response with `Content-Type: text/html; charset=utf-8`.
     */
    private function badRequest(string $message): ResponseInterface
    {
        $html = '<!DOCTYPE html><html><head><title>Authentication Error</title></head><body>'
            . '<h1>Authentication Error</h1><p>' . htmlspecialchars($message, ENT_QUOTES, 'UTF-8') . '</p>'
            . '<p><a href="/">Go to homepage</a></p>'
            . '</body></html>';

        $response = $this->responseFactory->createResponse(400);
        $response->getBody()->write($html);

        return $response->withHeader('Content-Type', 'text/html; charset=utf-8');
    }
}
