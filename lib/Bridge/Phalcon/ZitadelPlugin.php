<?php

declare(strict_types=1);

namespace Zitadel\Sdk\Bridge\Phalcon;

use Phalcon\Di\DiInterface;
use Phalcon\Events\Event;
use Phalcon\Http\Request;
use Phalcon\Http\Response;
use Phalcon\Mvc\Application;
use Phalcon\Mvc\DispatcherInterface;
use Zitadel\Sdk\Attribute\AllowAnonymous;
use Zitadel\Sdk\Auth\HttpProxy;
use Zitadel\Sdk\Auth\PkceFlow;
use Zitadel\Sdk\Auth\PkceStateCookie;
use Zitadel\Sdk\Auth\TokenValidator;
use Zitadel\Sdk\Config\ZitadelConfig;
use Zitadel\Sdk\Exception\PkceException;

/**
 * Phalcon MVC plugin that owns the complete Zitadel authentication lifecycle.
 *
 * Handles two events:
 *
 * **`application:beforeHandleRequest`** — fires before the router resolves
 * any controller. Intercepts callback and logout paths, validates tokens,
 * and triggers protected-route redirects.
 *
 * **`dispatch:beforeDispatch`** — fires after the dispatcher resolves the
 * controller+action, before execution. Checks `#[AllowAnonymous]` and
 * allows anonymous access when present.
 *
 * Registration in `app/config/services.php`:
 * ```php
 * $eventsManager = new EventsManager();
 * $eventsManager->attach('application', $plugin);
 * $eventsManager->attach('dispatch', $plugin);
 * $app->setEventsManager($eventsManager);
 * $app->getDI()->get('dispatcher')->setEventsManager($eventsManager);
 * ```
 *
 * `public/index.php` must handle the false return value:
 * ```php
 * $result = $app->handle($_SERVER['REQUEST_URI']);
 * if ($result !== false) {
 *     echo $result->getContent();
 * }
 * ```
 *
 * Access claims in controllers:
 * ```php
 * $claims = $this->di->get('zitadel.claims');
 * ```
 */
readonly class ZitadelPlugin
{
    public function __construct(
        private ZitadelConfig  $config,
        private TokenValidator $validator,
    ) {
    }

    /**
     * Fires before the Phalcon router handles the request.
     *
     * Returns false to stop the application when this plugin sends the response
     * (callback, logout, or protected-route redirect). Returning false signals
     * to `index.php` that `handle()` returned false and the response has already
     * been sent or is stored in the DI container.
     *
     * @param Event       $event       The Phalcon event object (unused).
     * @param Application $application The MVC application instance; provides the DI container.
     * @return bool True to continue routing, false when the response has already been sent.
     */
    public function beforeHandleRequest(Event $event, Application $application): bool
    {
        $di      = $application->getDI();
        $request = $di->get('request');
        $path    = '/' . ltrim($request->getURI(true), '/');

        // Handle proxy (before callback/logout — fires before routing)
        if (HttpProxy::isProxyPath($path, $this->config->proxyPath)) {
            $response = $this->handleProxy($request);
            $di->set('response', $response);
            $response->send();
            return false;
        }

        // Handle callback
        if ($path === $this->config->callbackPath) {
            $response = $this->handleCallback($request, $di);
            $di->set('response', $response);
            $response->send();
            return false;
        }

        // Handle logout
        if ($path === $this->config->logoutPath) {
            $response = $this->handleLogout($request);
            $di->set('response', $response);
            $response->send();
            return false;
        }

        // Ignored routes pass through
        if ($this->matchesRoutes($path, $this->config->ignoredRoutes)) {
            $di->set('zitadel.claims', static fn () => null);
            return true;
        }

        // Extract token (Bearer wins over cookie)
        $bearer = $request->getHeader('Authorization');
        $token  = null;
        if (str_starts_with($bearer, 'Bearer ')) {
            $token = substr($bearer, 7);
        } elseif (isset($_COOKIE['__nextgen_auth'])) {
            $token = $_COOKIE['__nextgen_auth'];
        }

        $claims = $token !== null ? $this->validator->validate((string) $token) : null;

        if ($claims !== null) {
            $di->set('zitadel.claims', $claims);
            return true;
        }

        // Store pending-protect flag; will check #[AllowAnonymous] at beforeDispatch
        if ($this->config->protectAll || $this->matchesRoutes($path, $this->config->protectedRoutes)) {
            $di->set('_zitadel_pending_redirect', true);
            return true;
        }

        // Public unauthenticated — delete stale cookies
        $di->set('zitadel.claims', static fn () => null);
        foreach (array_keys($_COOKIE) as $name) {
            if (str_starts_with((string) $name, '__nextgen')) {
                header($this->buildCookieHeader((string) $name, '', 1, $request->isSecure()), false);
            }
        }

        return true;
    }

    /**
     * Fires after the dispatcher resolves controller+action, before execution.
     *
     * Checks `#[AllowAnonymous]` when a protected redirect is pending.
     * If anonymous is allowed, clears the pending flag. Otherwise, redirects.
     *
     * @param Event               $event      The Phalcon event object (unused).
     * @param DispatcherInterface $dispatcher The MVC dispatcher; provides controller and action metadata.
     * @return bool True to allow dispatch to proceed, false when a redirect response has been sent.
     */
    public function beforeDispatch(Event $event, DispatcherInterface $dispatcher): bool
    {
        $di = $dispatcher->getDI();

        if (!$di->has('_zitadel_pending_redirect')) {
            return true;
        }

        $controllerClass = $dispatcher->getControllerClass();
        if (class_exists($controllerClass)) {
            $classRef    = new \ReflectionClass($controllerClass);
            $actionName  = $dispatcher->getActiveMethod();

            if (!empty($classRef->getAttributes(AllowAnonymous::class))) {
                $di->remove('_zitadel_pending_redirect');
                $di->set('zitadel.claims', static fn () => null);
                return true;
            }

            if ($classRef->hasMethod($actionName) &&
                !empty($classRef->getMethod($actionName)->getAttributes(AllowAnonymous::class))) {
                $di->remove('_zitadel_pending_redirect');
                $di->set('zitadel.claims', static fn () => null);
                return true;
            }
        }

        // Proceed with PKCE redirect
        $di->remove('_zitadel_pending_redirect');
        $request = $di->get('request');
        $next    = $request->getURI();
        if (!str_starts_with($next, '/')) {
            $next = '/' . $next;
        }

        $verifier  = PkceFlow::generateCodeVerifier();
        $state     = PkceFlow::generateState();
        $challenge = PkceFlow::generateCodeChallenge($verifier);
        $authUrl   = PkceFlow::buildAuthorizationUrl($this->config, $challenge, $state);
        $cookie    = PkceStateCookie::encrypt(
            $verifier,
            $state,
            $next,
            $this->config->cookieSecret
        );

        $response = new Response();
        $response->setStatusCode(302, 'Found');
        $response->setHeader('Location', $authUrl);
        $response->setContent('');
        $response->setRawHeader($this->buildCookieHeader('__nextgen_pkce', $cookie, time() + 600, $request->isSecure()));
        $di->set('response', $response);

        // Pre-populate the view content with '' so that Application::handle()
        // calling view->getContent() after finish() gets '' instead of null,
        // preventing the PHP 8.x null-to-string deprecation on Response::setContent().
        if ($di->has('view')) {
            $di->getShared('view')->setContent('');
        }

        $response->send();

        // Stop dispatch
        return false;
    }

    /**
     * Reverse-proxies a `/__nextgen/*` request to the upstream auth backend.
     *
     * Strips hop-by-hop and internal headers in both directions, appends
     * `REMOTE_ADDR` to the `X-Forwarded-For` chain, and upgrades `__nextgen*`
     * session cookies to `Secure` when the client connection is HTTPS.
     * `Set-Cookie` headers are emitted via `header(..., false)` to prevent
     * Phalcon's `Headers::send()` from overwriting earlier values with replace=true.
     * Returns a 502 Bad Gateway response on cURL failure.
     *
     * @param Request $request The incoming proxy request.
     * @return Response The upstream response (or 502 on failure).
     */
    private function handleProxy(Request $request): Response
    {
        $proxyPath = rtrim($this->config->proxyPath, '/');
        $rawPath   = '/' . ltrim($request->getURI(true), '/');
        $suffix    = substr($rawPath, strlen($proxyPath));
        $query     = $_SERVER['QUERY_STRING'] ?? '';
        $target    = $this->config->issuerUrl . $suffix . ($query !== '' ? '?' . $query : '');

        $headers = [];
        foreach ($_SERVER as $key => $value) {
            if (str_starts_with($key, 'HTTP_')) {
                $name          = str_replace('_', '-', substr($key, 5));
                $headers[$name] = (string) $value;
            }
        }
        if (isset($_SERVER['CONTENT_TYPE'])) {
            $headers['Content-Type'] = (string) $_SERVER['CONTENT_TYPE'];
        }

        $method     = $request->getMethod();
        $hasBody    = !in_array(strtoupper($method), ['GET', 'HEAD'], true);
        $body       = $hasBody ? (string) file_get_contents('php://input') : '';
        $remoteAddr = $_SERVER['REMOTE_ADDR'] ?? '';
        $host       = $_SERVER['HTTP_HOST'] ?? $request->getServerName();
        $proto      = $request->isSecure() ? 'https' : 'http';
        $isSecure   = $request->isSecure();

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
            $response = new Response();
            $response->setStatusCode(502);
            $response->setContentType('text/plain', 'utf-8');
            $response->setContent('Bad Gateway');

            return $response;
        }

        foreach ($result['setCookies'] as $cookie) {
            header('Set-Cookie: ' . HttpProxy::upgradeSessionCookie($cookie, $isSecure), false);
        }

        $response = new Response();
        $response->setStatusCode($result['status']);

        foreach ($result['headers'] as $name => $values) {
            $response->setHeader($name, implode(', ', $values));
        }

        $response->setContent($result['body']);

        return $response;
    }

    /**
     * Validates the PKCE state cookie, exchanges the authorization code, and redirects
     * to the originally requested path with the session cookie set.
     *
     * Emits `Set-Cookie` headers directly via `header(..., false)` to prevent Phalcon's
     * `Headers::send()` from overwriting the first cookie with the second.
     *
     * @param Request     $request The callback request containing `code` and `state` query params.
     * @param DiInterface $di      The DI container (unused here but present for symmetry with callers).
     * @return Response A redirect response, or a 400 error response on any validation failure.
     */
    private function handleCallback(Request $request, DiInterface $di): Response
    {
        $pkceValue = $_COOKIE['__nextgen_pkce'] ?? null;
        if (!is_string($pkceValue) || $pkceValue === '') {
            return $this->badRequest('Authentication failed — PKCE state cookie missing. Please try signing in again.');
        }

        $pkce = PkceStateCookie::decrypt($pkceValue, $this->config->cookieSecret);
        if ($pkce === null) {
            return $this->badRequest('Authentication failed — PKCE state cookie invalid. Please try signing in again.');
        }

        $state = $request->getQuery('state');
        if (!hash_equals($pkce['state'], (string) $state)) {
            return $this->badRequest('Authentication failed — state parameter mismatch. Please try signing in again.');
        }

        $code = $request->getQuery('code');
        if (!is_string($code) || $code === '') {
            $oauthError = $request->getQuery('error_description') ?? $request->getQuery('error') ?? 'Missing code';
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

        // Use header() directly with replace=false so both Set-Cookie headers survive.
        // Phalcon's Headers::send() calls header() with replace=true (the default), which
        // means the second Set-Cookie would silently overwrite the first, losing the auth
        // cookie before it ever reaches the browser.
        header($this->buildCookieHeader('__nextgen_auth', $tokenToValidate, time() + $maxAge, $secure), false);
        header($this->buildCookieHeader('__nextgen_pkce', '', 1, $secure), false);

        $response = new Response();
        $response->setStatusCode(302, 'Found');
        $response->setHeader('Location', $next);
        $response->setContent('');

        return $response;
    }

    /**
     * Clears the session cookie and redirects to Zitadel's end-session endpoint.
     *
     * @param Request $request The logout request (scheme is used for the cookie Secure flag).
     * @return Response A redirect response to the OIDC end-session endpoint.
     */
    private function handleLogout(Request $request): Response
    {
        header($this->buildCookieHeader('__nextgen_auth', '', 1, $request->isSecure()), false);

        $params   = http_build_query(['client_id' => $this->config->clientId, 'post_logout_redirect_uri' => $this->config->postLogoutAbsoluteUri()]);
        $location = $this->config->endSessionEndpoint() . '?' . $params;
        $response = new Response();
        $response->setStatusCode(302, 'Found');
        $response->setHeader('Location', $location);
        $response->setContent('');

        return $response;
    }

    /**
     * Returns true when `$path` matches any entry in `$routes`.
     *
     * Entries ending with `*` are treated as prefix wildcards. All other entries
     * are matched by strict equality.
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
     * Builds a raw `Set-Cookie` header string for a given cookie name and value.
     *
     * Must be emitted via `header($str, false)` rather than through Phalcon's response
     * headers API, which calls `header()` with `replace=true` and would overwrite earlier
     * `Set-Cookie` headers from the same response.
     *
     * @param string $name   Cookie name.
     * @param string $value  Cookie value (URL-encoded before inclusion).
     * @param int    $expire Unix timestamp for the `Expires` attribute.
     * @param bool   $secure Whether to add the `Secure` attribute.
     * @return string A complete `Set-Cookie: ...` header string.
     */
    private function buildCookieHeader(string $name, string $value, int $expire, bool $secure): string
    {
        $parts = [
            $name . '=' . urlencode($value),
            'Expires=' . gmdate('D, d M Y H:i:s T', $expire),
            'Path=/',
            'SameSite=Lax',
            'HttpOnly',
        ];
        if ($secure) {
            $parts[] = 'Secure';
        }

        return 'Set-Cookie: ' . implode('; ', $parts);
    }

    /**
     * Builds a 400 Bad Request HTML error response with a human-readable message.
     *
     * @param string $message The authentication error description shown to the user.
     * @return Response A 400 response with `Content-Type: text/html; charset=UTF-8`.
     */
    private function badRequest(string $message): Response
    {
        $html = '<!DOCTYPE html><html><head><title>Authentication Error</title></head><body>'
            . '<h1>Authentication Error</h1><p>' . htmlspecialchars($message, ENT_QUOTES, 'UTF-8') . '</p>'
            . '<p><a href="javascript:history.back()">Go back</a></p>'
            . '</body></html>';

        $response = new Response();
        $response->setStatusCode(400);
        $response->setContentType('text/html', 'UTF-8');
        $response->setContent($html);

        return $response;
    }
}
