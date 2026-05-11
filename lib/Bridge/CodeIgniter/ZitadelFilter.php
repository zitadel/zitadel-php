<?php

declare(strict_types=1);

namespace Zitadel\Sdk\Bridge\CodeIgniter;

use CodeIgniter\Filters\FilterInterface;
use CodeIgniter\HTTP\IncomingRequest;
use CodeIgniter\HTTP\RedirectResponse;
use CodeIgniter\HTTP\RequestInterface;
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
 * `service('router')->controllerName()` returns the FQCN, and
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
     *
     * @param RequestInterface $request   The incoming HTTP request.
     * @param array<mixed>|null $arguments Optional filter arguments (unused).
     * @return ResponseInterface|null Response to short-circuit, or null to continue routing.
     */
    #[\Override]
    public function before(RequestInterface $request, $arguments = null): ?ResponseInterface
    {
        if (!$request instanceof IncomingRequest) {
            return null;
        }

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
                '',     // domain
                '/',    // path
                '',     // prefix
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

    /**
     * Post-processing hook — no action needed; returns the response unchanged.
     *
     * @param RequestInterface  $request   The processed HTTP request.
     * @param ResponseInterface $response  The outgoing response.
     * @param array<mixed>|null $arguments Optional filter arguments (unused).
     * @return ResponseInterface The unmodified response.
     */
    #[\Override]
    public function after(RequestInterface $request, ResponseInterface $response, $arguments = null): ResponseInterface
    {
        return $response;
    }

    /**
     * Validates the PKCE state cookie, exchanges the authorization code, validates the
     * resulting access token, and redirects to the originally requested path.
     *
     * @param IncomingRequest $request The callback request containing `code` and `state` query params.
     * @return ResponseInterface Redirect with `__nextgen_auth` cookie set, or a 400 error response.
     */
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
        if (!hash_equals($pkce['state'], (string) $state)) {
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

        $tokenToValidate = PkceFlow::selectToken($tokens);
        if ($tokenToValidate === null) {
            return $this->badRequest('Authentication failed — no usable token in response.');
        }

        $claims = $this->validator->validate($tokenToValidate);
        if ($claims === null) {
            return $this->badRequest('Authentication failed — could not validate the token received from the identity provider.');
        }

        $next   = $this->sanitizeNext($pkce['next']) ?? $this->config->postLoginRedirect;
        $maxAge = max(0, $claims->exp - time());
        $secure = $request->isSecure();

        $response = response()->redirect($next);
        $response->setCookie('__nextgen_auth', $tokenToValidate, $maxAge, '', '/', '', $secure, true, 'Lax');
        $response->deleteCookie('__nextgen_pkce', '', '/');

        return $response;
    }

    /**
     * Clears the session cookie and redirects to Zitadel's end-session endpoint.
     *
     * @param IncomingRequest $request The logout request (used to determine scheme for cookie flags).
     * @return ResponseInterface Redirect to the OIDC end-session endpoint with the auth cookie deleted.
     */
    private function handleLogout(IncomingRequest $request): ResponseInterface
    {
        $params   = http_build_query(['client_id' => $this->config->clientId, 'post_logout_redirect_uri' => $this->config->postLogoutAbsoluteUri()]);
        $response = response()->redirect($this->config->endSessionEndpoint() . '?' . $params);
        $response->deleteCookie('__nextgen_auth', '', '/');

        return $response;
    }

    /**
     * Returns true when the matched controller class or action method carries
     * a {@see \Zitadel\Sdk\Attribute\AllowAnonymous} attribute.
     *
     * @return bool True if anonymous access is permitted for the current route.
     */
    private function hasAllowAnonymous(): bool
    {
        try {
            $router = service('router');
            $controllerClass = $router->controllerName();
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

    /**
     * Returns true when `$path` matches any entry in `$routes`.
     *
     * Entries ending with `*` are treated as prefix wildcards (`/api/*` matches `/api/v1/users`).
     * All other entries are matched by strict equality.
     *
     * @param string   $path   The request path to test.
     * @param string[] $routes Route patterns to match against.
     * @return bool True if any pattern matches the given path.
     */
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

    /**
     * Validates that `$next` is a safe relative path suitable for use as a post-login redirect.
     *
     * Rejects absolute URLs, protocol-relative URLs (`//`), and paths containing backslashes
     * to prevent open-redirect vulnerabilities.
     *
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
     * Builds a 400 Bad Request HTML error response with a human-readable message.
     *
     * @param string $message The authentication error description shown to the user.
     * @return ResponseInterface A 400 response with `Content-Type: text/html; charset=utf-8`.
     */
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
