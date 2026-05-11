<?php

declare(strict_types=1);

namespace Zitadel\Sdk\Bridge\Yii;

use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Yiisoft\Router\Route;
use Yiisoft\Router\UrlMatcherInterface;
use Zitadel\Sdk\Attribute\AllowAnonymous;
use Zitadel\Sdk\Auth\PkceFlow;
use Zitadel\Sdk\Auth\PkceStateCookie;
use Zitadel\Sdk\Auth\TokenValidator;
use Zitadel\Sdk\Config\ZitadelConfig;

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
    public function __construct(
        private ZitadelConfig            $config,
        private TokenValidator           $validator,
        private ResponseFactoryInterface $responseFactory,
        private UrlMatcherInterface      $urlMatcher,
    ) {
    }

    #[\Override]
    public function process(
        ServerRequestInterface  $request,
        RequestHandlerInterface $handler,
    ): ResponseInterface {
        $uri      = $request->getUri();
        $path     = $uri->getPath();
        $isSecure = $uri->getScheme() === 'https';

        // Step 1 — callback
        if ($path === $this->config->callbackPath) {
            return $this->handleCallback($request, $isSecure);
        }

        // Step 2 — logout
        if ($path === $this->config->logoutPath) {
            return $this->handleLogout($request);
        }

        // Step 3 — ignored routes
        if ($this->matchesRoutes($path, $this->config->ignoredRoutes)) {
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
        if ($this->config->protectAll || $this->matchesRoutes($path, $this->config->protectedRoutes)) {
            return $this->redirectToLogin($request, $isSecure);
        }

        // Step 8 — public unauthenticated
        $response = $handler->handle($request->withAttribute('zitadel.claims', null));

        return $this->deleteStaleNextgenCookies($response, $request);
    }

    /**
     * Pre-resolves the matched route via `UrlMatcherInterface` and reflects on its
     * action class (the last element of `getData('enabledMiddlewares')`) for the
     * `#[AllowAnonymous]` attribute.
     *
     * Does NOT call `CurrentRoute::setRouteWithArguments()` — that is left to the
     * downstream Router middleware so the single-assignment constraint is not violated.
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
     * Returns the middleware definitions registered on a route.
     *
     * `Route::$middlewareDefinitions` is private with no public accessor in
     * `yiisoft/router` 3.x. We read it via reflection rather than relying on
     * internal `getData()` keys whose availability varies across minor versions.
     *
     * @param Route $route The matched route.
     * @return array<array|callable|string> The middleware definitions (action is last).
     */
    private function routeMiddlewareDefinitions(Route $route): array
    {
        try {
            $prop = new \ReflectionProperty($route, 'middlewareDefinitions');

            return (array) $prop->getValue($route);
        } catch (\ReflectionException) {
            return [];
        }
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

        if ($pkce === null) {
            return $this->badRequest('Authentication failed — PKCE state cookie missing or invalid. Please try signing in again.');
        }

        $params = $request->getQueryParams();
        $code   = $params['code'] ?? null;
        $state  = $params['state'] ?? null;

        if (!hash_equals($pkce['state'], (string) $state)) {
            return $this->badRequest('Authentication failed — state parameter mismatch. Please try signing in again.');
        }

        if (!is_string($code) || $code === '') {
            $oauthError = $params['error_description'] ?? $params['error'] ?? 'Missing code parameter';
            return $this->badRequest("Authentication failed — {$oauthError}. Please try signing in again.");
        }

        $baseResponse = PkceStateCookie::delete($this->responseFactory->createResponse(302));

        try {
            $tokens = PkceFlow::exchangeCode($this->config, $code, $pkce['verifier']);
        } catch (\Zitadel\Sdk\Exception\PkceException $e) {
            return $this->badRequest('Authentication failed — token exchange error: ' . $e->getMessage());
        }

        $accessToken = $tokens['access_token'] ?? null;
        if (!is_string($accessToken)) {
            return $this->badRequest('Authentication failed — no access token in response.');
        }

        $claims = $this->validator->validate($accessToken);
        if ($claims === null) {
            return $this->badRequest('Authentication failed — could not validate the token received from the identity provider.');
        }

        $maxAge  = max(0, $claims->exp - time());
        $secure  = $isSecure ? '; Secure' : '';
        $cookie  = "__nextgen_auth={$accessToken}; Max-Age={$maxAge}; Path=/; HttpOnly; SameSite=Lax{$secure}";

        $next = $this->sanitizeNext($pkce['next']) ?? $this->config->postLoginRedirect;

        return $baseResponse
            ->withAddedHeader('Set-Cookie', $cookie)
            ->withHeader('Location', $next);
    }

    /**
     * Clears the session cookie and redirects to Zitadel's end-session endpoint.
     *
     * @param ServerRequestInterface $request The logout request.
     * @return ResponseInterface A 302 redirect to the OIDC end-session endpoint.
     */
    private function handleLogout(ServerRequestInterface $request): ResponseInterface
    {
        $params = http_build_query([
            'post_logout_redirect_uri' => $this->config->postLogoutRedirect,
        ]);

        $response = $this->responseFactory->createResponse(302)
            ->withHeader('Location', $this->config->endSessionEndpoint() . '?' . $params)
            ->withAddedHeader('Set-Cookie', '__nextgen_auth=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax');

        return $this->deleteStaleNextgenCookies($response, $request);
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

        return PkceStateCookie::write($response, $verifier, $state, $next, $this->config->cookieSecret, $isSecure);
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
        if (str_starts_with($authHeader, 'Bearer ')) {
            return substr($authHeader, 7);
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
    ): ResponseInterface {
        $cookies = $request->getCookieParams();
        foreach (array_keys($cookies) as $name) {
            if (str_starts_with((string) $name, '__nextgen')) {
                $response = $response->withAddedHeader(
                    'Set-Cookie',
                    "{$name}=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax"
                );
            }
        }

        return $response;
    }

    /** @param string[] $routes */
    private function matchesRoutes(string $path, array $routes): bool
    {
        if ($routes === []) {
            return false;
        }

        foreach ($routes as $pattern) {
            if (str_ends_with($pattern, '*')) {
                if (str_starts_with($path, substr($pattern, 0, -1))) {
                    return true;
                }
            } elseif ($path === $pattern) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param string $next The candidate redirect path from the PKCE state cookie.
     * @return string|null The sanitized path, or null if the input is unsafe.
     */
    private function sanitizeNext(string $next): ?string
    {
        if (!str_starts_with($next, '/') || str_starts_with($next, '//')) {
            return null;
        }

        if (str_contains($next, '\\')) {
            return null;
        }

        if (parse_url($next, PHP_URL_SCHEME) !== null) {
            return null;
        }

        return $next;
    }

    /**
     * @param string $message The authentication error description.
     * @return ResponseInterface A 400 response with `Content-Type: text/html; charset=utf-8`.
     */
    private function badRequest(string $message): ResponseInterface
    {
        $html = '<!DOCTYPE html><html><head><title>Authentication Error</title></head><body>'
            . '<h1>Authentication Error</h1><p>' . htmlspecialchars($message, ENT_QUOTES, 'UTF-8') . '</p>'
            . '<p><a href="javascript:history.back()">Go back</a></p>'
            . '</body></html>';

        $response = $this->responseFactory->createResponse(400);
        $response->getBody()->write($html);

        return $response->withHeader('Content-Type', 'text/html; charset=utf-8');
    }
}
