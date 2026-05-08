<?php

declare(strict_types=1);

namespace Zitadel\Sdk\Bridge\CodeIgniter;

use CodeIgniter\Filters\FilterInterface;
use CodeIgniter\HTTP\IncomingRequest;
use CodeIgniter\HTTP\RedirectResponse;
use CodeIgniter\HTTP\Response;
use CodeIgniter\HTTP\ResponseInterface;
use Zitadel\Sdk\Attribute\AllowAnonymous;
use Zitadel\Sdk\Auth\PkceFlow;
use Zitadel\Sdk\Auth\PkceStateCookie;
use Zitadel\Sdk\Auth\TokenValidator;
use Zitadel\Sdk\Config\ZitadelConfig;
use Zitadel\Sdk\Exception\PkceException;

/**
 * CI4 filter that owns the complete Zitadel authentication lifecycle.
 *
 * Register in `app/Config/Filters.php`:
 * ```php
 * public array $aliases = ['zitadel' => ZitadelFilter::class];
 * public array $globals = ['before' => ['zitadel']];
 * ```
 *
 * No custom routes are needed. The filter intercepts the callback and logout
 * paths before CI4's router runs by returning a {@see ResponseInterface} from
 * `before()`, which short-circuits dispatch entirely.
 *
 * After successful validation, authenticated claims are stored in
 * {@see ZitadelHolder} for controller access via `ZitadelHolder::claims()`.
 *
 * `#[AllowAnonymous]` is supported: after routing resolves the controller,
 * `service('router')->getController()` returns the FQCN, and
 * `service('router')->methodName()` returns the action name for reflection.
 */
final readonly class ZitadelFilter implements FilterInterface
{
    public function __construct(
        private ZitadelConfig  $config,
        private TokenValidator $validator,
    ) {
    }

    /**
     * Intercepts the request before routing.
     *
     * Returns a CI4 `ResponseInterface` to short-circuit when handling the
     * callback, logout, or a protected-route redirect. Returns null to pass
     * control to the router for all other requests.
     */
    #[\Override]
    public function before(IncomingRequest $request, $arguments = null): ?ResponseInterface
    {
        $path = '/' . ltrim($request->getPath(), '/');

        // Handle callback
        if ($path === $this->config->callbackPath) {
            return $this->handleCallback($request);
        }

        // Handle logout
        if ($path === $this->config->logoutPath) {
            return $this->handleLogout($request);
        }

        // Ignored routes pass through
        if ($this->matchesRoutes($path, $this->config->ignoredRoutes)) {
            ZitadelHolder::set(null);
            return null;
        }

        // Extract token (Bearer wins over cookie)
        $bearer = $request->getHeaderLine('Authorization');
        $token  = null;
        if (str_starts_with($bearer, 'Bearer ')) {
            $token = substr($bearer, 7);
        } elseif (!empty($request->getCookie('__nextgen_auth'))) {
            $token = $request->getCookie('__nextgen_auth');
        }

        $claims = $token !== null ? $this->validator->validate((string) $token) : null;

        if ($claims !== null) {
            ZitadelHolder::set($claims);
            return null;
        }

        // Check #[AllowAnonymous] on the resolved controller method or class
        if ($this->hasAllowAnonymous()) {
            ZitadelHolder::set(null);
            return null;
        }

        // Protect route
        if ($this->config->protectAll || $this->matchesRoutes($path, $this->config->protectedRoutes)) {
            $verifier  = PkceFlow::generateCodeVerifier();
            $state     = PkceFlow::generateState();
            $challenge = PkceFlow::generateCodeChallenge($verifier);
            $authUrl   = PkceFlow::buildAuthorizationUrl($this->config, $challenge, $state);
            $next      = $request->getPath() . ($request->getUri()->getQuery() !== '' ? '?' . $request->getUri()->getQuery() : '');
            if (!str_starts_with($next, '/')) {
                $next = '/' . $next;
            }

            $cookie = PkceStateCookie::encrypt(
                $verifier,
                $state,
                $next,
                $this->config->cookieSecret
            );

            $response = response()->redirect($authUrl);
            $response->setCookie(
                '__nextgen_pkce',
                $cookie,
                600,
                '/',
                '',
                $request->isSecure(),
                true,
                'Lax'
            );

            return $response;
        }

        // Public unauthenticated — delete stale __nextgen* cookies
        ZitadelHolder::set(null);
        $response = service('response');
        foreach ($request->getCookieNames() as $name) {
            if (str_starts_with((string) $name, '__nextgen')) {
                $response->deleteCookie((string) $name, '', '/');
            }
        }

        return null;
    }

    #[\Override]
    public function after(IncomingRequest $request, ResponseInterface $response, $arguments = null): ResponseInterface
    {
        return $response;
    }

    private function handleCallback(IncomingRequest $request): ResponseInterface
    {
        $pkceValue = $request->getCookie('__nextgen_pkce');
        if (!is_string($pkceValue) || $pkceValue === '') {
            return $this->badRequest('Authentication failed — PKCE state cookie missing. Please try signing in again.');
        }

        $pkce = PkceStateCookie::decrypt($pkceValue, $this->config->cookieSecret);
        if ($pkce === null) {
            return $this->badRequest('Authentication failed — PKCE state cookie invalid. Please try signing in again.');
        }

        $state = $request->getGet('state');
        if ($state !== $pkce['state']) {
            return $this->badRequest('Authentication failed — state parameter mismatch. Please try signing in again.');
        }

        $code = $request->getGet('code');
        if (!is_string($code) || $code === '') {
            $oauthError = $request->getGet('error_description') ?? $request->getGet('error') ?? 'Missing code';
            return $this->badRequest("Authentication failed — {$oauthError}. Please try signing in again.");
        }

        try {
            $tokens = PkceFlow::exchangeCode($this->config, $code, $pkce['verifier']);
        } catch (PkceException $e) {
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

        $next   = $this->sanitizeNext($pkce['next']) ?? $this->config->postLoginRedirect;
        $maxAge = max(0, $claims->exp - time());
        $secure = $request->isSecure();

        $response = response()->redirect($next);
        $response->setCookie('__nextgen_auth', $accessToken, $maxAge, '/', '', $secure, true, 'Lax');
        $response->deleteCookie('__nextgen_pkce', '', '/');

        return $response;
    }

    private function handleLogout(IncomingRequest $request): ResponseInterface
    {
        $params   = http_build_query(['post_logout_redirect_uri' => $this->config->postLogoutRedirect]);
        $response = response()->redirect($this->config->endSessionEndpoint() . '?' . $params);
        $response->deleteCookie('__nextgen_auth', '', '/');

        return $response;
    }

    private function hasAllowAnonymous(): bool
    {
        try {
            $router = service('router');
            $controllerClass = $router->getController();
            $actionMethod    = $router->methodName();
        } catch (\Throwable) {
            return false;
        }

        if ($controllerClass === null || !class_exists($controllerClass)) {
            return false;
        }

        $classRef = new \ReflectionClass($controllerClass);
        if (!empty($classRef->getAttributes(AllowAnonymous::class))) {
            return true;
        }

        if ($actionMethod !== null && $classRef->hasMethod($actionMethod)) {
            return !empty($classRef->getMethod($actionMethod)->getAttributes(AllowAnonymous::class));
        }

        return false;
    }

    private function matchesRoutes(string $path, array $routes): bool
    {
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

        return service('response')
            ->setStatusCode(400)
            ->setContentType('text/html; charset=utf-8')
            ->setBody($html);
    }
}
