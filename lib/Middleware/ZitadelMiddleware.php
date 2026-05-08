<?php

declare(strict_types=1);

namespace Zitadel\Sdk\Middleware;

use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Zitadel\Sdk\Attribute\AllowAnonymous;
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

        // Step 6a — #[AllowAnonymous] check (Mezzio/Yii 3: route resolved before middleware)
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

    private function handleCallback(ServerRequestInterface $request, bool $isSecure): ResponseInterface
    {
        $pkce = PkceStateCookie::read($request, $this->config->cookieSecret);

        if ($pkce === null) {
            return $this->badRequest('Authentication failed — PKCE state cookie missing or invalid. Please try signing in again.');
        }

        $params = $request->getQueryParams();
        $code   = $params['code'] ?? null;
        $state  = $params['state'] ?? null;

        if ($state !== $pkce['state']) {
            return $this->badRequest('Authentication failed — state parameter mismatch. Please try signing in again.');
        }

        if (!is_string($code) || $code === '') {
            $oauthError = $params['error_description'] ?? $params['error'] ?? 'Missing code parameter';
            return $this->badRequest("Authentication failed — {$oauthError}. Please try signing in again.");
        }

        // Delete PKCE cookie immediately (single-use) before code exchange
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

        return PkceStateCookie::write($response, $verifier, $state, $next, $this->config->cookieSecret, $isSecure);
    }

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

    private function deleteStaleNextgenCookies(
        ResponseInterface $response,
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

    private function hasAllowAnonymous(ServerRequestInterface $request): bool
    {
        // RouteResult attribute is set by Mezzio's RouteMiddleware and some Yii 3 routers
        $routeResult = $request->getAttribute('Mezzio\Router\RouteResult');
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
