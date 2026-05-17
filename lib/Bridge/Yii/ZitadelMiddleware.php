<?php

declare(strict_types=1);

namespace Zitadel\Sdk\Bridge\Yii;

use Psr\EventDispatcher\EventDispatcherInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Yiisoft\Router\Route;
use Yiisoft\Router\UrlMatcherInterface;
use Zitadel\Sdk\Attribute\AllowAnonymous;
use Zitadel\Sdk\Auth\HttpProxy;
use Zitadel\Sdk\Auth\PkceFlow;
use Zitadel\Sdk\Auth\PkceStateCookie;
use Zitadel\Sdk\Auth\TokenValidator;
use Zitadel\Sdk\Config\ZitadelConfig;
use Zitadel\Sdk\Event\ZitadelLoginEvent;
use Zitadel\Sdk\Event\ZitadelLogoutEvent;

/**
 * PSR-15 middleware for Yii 3 applications.
 *
 * Functionally identical to {@see \Zitadel\Sdk\Middleware\ZitadelMiddleware} except
 * that `#[AllowAnonymous]` detection uses Yii's `UrlMatcherInterface` to pre-resolve
 * the matched route and reflect on its action class — rather than reading the
 * Mezzio-specific `Mezzio\Router\RouteResult` request attribute that Yii never sets.
 *
 * Register this middleware as the outermost layer in your PSR-15 pipeline, wrapping
 * Yii's own `Router` middleware so that `/callback` and `/logout` are intercepted
 * before routing runs:
 *
 * ```php
 * // application.php
 * 'middlewares' => [
 *     ZitadelMiddleware::class,          // outermost — handles auth lifecycle
 *     \Yiisoft\Router\Middleware\Router::class,  // inner — routes + dispatches
 * ],
 * ```
 *
 * `UrlMatcherInterface::match()` is called once here (step 6a) to resolve the action
 * class for attribute reflection, and a second time inside the downstream Router
 * middleware for actual dispatch. The double call is intentional — the bridge must
 * not call `CurrentRoute::setRouteWithArguments()`, which would throw on the Router's
 * subsequent call since that setter is single-assignment.
 *
 * Processing order per request:
 *
 * 1. **Callback** (`callbackPath`): validates PKCE state cookie, asserts `state` param,
 *    exchanges code, validates token, sets auth cookie, redirects.
 * 2. **Logout** (`logoutPath`): deletes auth cookie, redirects to end-session endpoint.
 * 3. **Ignored routes** (`ignoredRoutes`): passes through without token validation.
 * 4. **Token extraction**: prefers `Authorization: Bearer` over `__nextgen_auth` cookie.
 * 5. **Token validation**: validates via {@see TokenValidator}.
 * 6. **Authenticated**: attaches {@see \Zitadel\Sdk\Auth\Claims} to `zitadel.claims` attribute.
 * 6a. **`#[AllowAnonymous]` check**: pre-resolves route via `UrlMatcherInterface`; reflects
 *     on the action class for the attribute; passes through if found.
 * 7. **Protected route**: generates PKCE challenge, stores state cookie, redirects to Zitadel.
 * 8. **Public unauthenticated**: attaches null to `zitadel.claims`, cleans up stale cookies.
 */
final readonly class ZitadelMiddleware implements MiddlewareInterface
{
    /**
     * @param ZitadelConfig            $config          SDK configuration (issuer, cookie secret, route paths).
     * @param TokenValidator           $validator       JWT validator backed by the shared JWKS cache.
     * @param ResponseFactoryInterface $responseFactory PSR-17 factory for creating redirect and error responses.
     * @param UrlMatcherInterface      $urlMatcher      Yii URL matcher used for `#[AllowAnonymous]` reflection.
     */
    public function __construct(
        private ZitadelConfig             $config,
        private TokenValidator            $validator,
        private ResponseFactoryInterface  $responseFactory,
        private UrlMatcherInterface       $urlMatcher,
        private ?EventDispatcherInterface $eventDispatcher = null,
    ) {
    }

    /**
     * Processes an incoming server request and returns a response.
     *
     * Intercepts the full Zitadel authentication lifecycle: proxy, callback, logout, ignored
     * routes, token validation, `#[AllowAnonymous]` reflection via Yii's URL matcher,
     * protected-route redirect, and stale-cookie cleanup for public unauthenticated requests.
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

        // Step 6a — #[AllowAnonymous] check via Yii URL matcher
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
     * Pre-resolves the matched route via `UrlMatcherInterface` and reflects on its
     * action class (the last element of `getData('enabledMiddlewares')`) for the
     * `#[AllowAnonymous]` attribute.
     *
     * Uses {@see Route::getData()} with key `'enabledMiddlewares'` to obtain the
     * middleware stack — the last element is the action handler. Does NOT call
     * `CurrentRoute::setRouteWithArguments()`, leaving that to the downstream
     * Router middleware so the single-assignment constraint is not violated.
     *
     * @param ServerRequestInterface $request The current request.
     * @return bool True if the matched action class or its `__invoke` method carries
     *              `#[AllowAnonymous]`.
     */
    private function hasAllowAnonymous(ServerRequestInterface $request): bool
    {
        try {
            $result = $this->urlMatcher->match($request);
        } catch (\Throwable) {
            return false;
        }

        if (!$result->isSuccess()) {
            return false;
        }

        $definitions = $this->routeMiddlewareDefinitions($result->route());
        if ($definitions === []) {
            return false;
        }

        // The action is the last element — set via Route::action() which appends to the array.
        $action = end($definitions);
        if (!is_string($action) || !class_exists($action)) {
            return false;
        }

        $ref = new \ReflectionClass($action);
        if (!empty($ref->getAttributes(AllowAnonymous::class))) {
            return true;
        }

        if ($ref->hasMethod('__invoke')) {
            return !empty($ref->getMethod('__invoke')->getAttributes(AllowAnonymous::class));
        }

        return false;
    }

    /**
     * Returns the enabled middleware definitions registered on a route.
     *
     * Uses {@see Route::getData()} with key `'enabledMiddlewares'` — the stable
     * public API that respects any `disableMiddleware()` exclusions applied to
     * the route. The action handler is always the last element in this list.
     *
     * @param Route $route The matched route.
     * @return array<array|callable|string> The enabled middleware definitions (action is last).
     */
    private function routeMiddlewareDefinitions(Route $route): array
    {
        /** @var array<array|callable|string> $definitions */
        $definitions = $route->getData('enabledMiddlewares');

        return $definitions;
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

        if (str_contains($suffix, '..')) {
            $response = $this->responseFactory->createResponse(400);
            $response->getBody()->write('Bad Request');

            return $response->withHeader('Content-Type', 'text/plain; charset=utf-8');
        }

        $query  = $uri->getQuery();
        $target = $this->config->issuerUrl . $suffix . ($query !== '' ? '?' . $query : '');

        $headers = [];
        foreach ($request->getHeaders() as $name => $values) {
            $headers[$name] = implode(', ', $values);
        }

        // Mirror Next.js/Nuxt behavior: consider X-Forwarded-Proto so that session
        // cookies get the Secure flag even when TLS is terminated at a load balancer.
        // Only honoured when trustXForwardedProto is true (the default) to allow
        // deployments behind untrusted networks to opt out.
        $cookiesSecure = $isSecure || ($this->config->trustXForwardedProto
            && strtolower($request->getHeaderLine('X-Forwarded-Proto')) === 'https');

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
            // Log the OAuth error server-side only — do not reflect it back to the
            // browser, as an attacker can craft a callback URL with an arbitrary
            // error_description to create a convincing phishing page (CWE-116).
            $oauthError = $params['error_description'] ?? $params['error'] ?? 'no error param';
            error_log('[zitadel] Callback missing code: ' . $oauthError);
            return $this->badRequest('Authentication failed — authorization code missing. Please try signing in again.')
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

        // Defence-in-depth: confirm the token is header-safe before writing the cookie.
        if (preg_match('/^[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+$/', $tokenToValidate) !== 1) {
            return $this->badRequest('Authentication failed — token contains unsafe characters.')
                ->withAddedHeader('Set-Cookie', $pkceDeleteCookie);
        }

        $maxAge = max(0, $claims->exp - time());
        $secure = $isSecure ? '; Secure' : '';
        $next   = PkceFlow::sanitizeNext($pkce['next']) ?? $this->config->postLoginRedirect;

        $this->eventDispatcher?->dispatch(new ZitadelLoginEvent($claims));

        return $this->responseFactory->createResponse(302)
            ->withAddedHeader('Set-Cookie', $pkceDeleteCookie)
            ->withAddedHeader('Set-Cookie', "__nextgen_auth={$tokenToValidate}; Max-Age={$maxAge}; Path=/; HttpOnly; SameSite=Lax{$secure}")
            ->withHeader('Location', $next);
    }

    /**
     * Clears the session cookie and redirects to Zitadel's end-session endpoint.
     *
     * @param ServerRequestInterface $request  The logout request.
     * @param bool                   $isSecure Whether the client-facing connection is HTTPS.
     * @return ResponseInterface A 302 redirect to the OIDC end-session endpoint.
     */
    private function handleLogout(ServerRequestInterface $request, bool $isSecure): ResponseInterface
    {
        $this->eventDispatcher?->dispatch(new ZitadelLogoutEvent());

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
     * @param ServerRequestInterface $request  The protected request being redirected.
     * @param bool                   $isSecure Whether the request was made over HTTPS.
     * @return ResponseInterface A 302 redirect to the Zitadel authorization endpoint.
     */
    private function redirectToLogin(ServerRequestInterface $request, bool $isSecure): ResponseInterface
    {
        $uri   = $request->getUri();
        $next  = $uri->getPath();
        $query = $uri->getQuery();
        if ($query !== '') {
            $next .= '?' . $query;
        }

        $verifier  = PkceFlow::generateCodeVerifier();
        $state     = PkceFlow::generateState();
        $challenge = PkceFlow::generateCodeChallenge($verifier);
        $authUrl   = PkceFlow::buildAuthorizationUrl($this->config, $challenge, $state);

        $response = $this->responseFactory->createResponse(302)->withHeader('Location', $authUrl);

        return PkceStateCookie::write($response, $verifier, $state, $next, $this->config->cookieSecret, $isSecure, $this->config->pkceCookieTtlSeconds);
    }

    /**
     * Extracts the raw JWT — preferring `Authorization: Bearer` over the auth cookie.
     *
     * @param ServerRequestInterface $request The incoming request.
     * @return string|null The raw token, or null if neither source is present.
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
     * Appends expired `Set-Cookie` headers to delete every `__nextgen*` cookie on
     * the incoming request.
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
