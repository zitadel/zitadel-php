<?php

declare(strict_types=1);

namespace Zitadel\Sdk\Bridge\Phalcon;

use Phalcon\Events\ManagerInterface as EventsManagerInterface;
use Phalcon\Http\Request;
use Phalcon\Http\Response;
use Phalcon\Mvc\Micro;
use Phalcon\Mvc\Micro\MiddlewareInterface;
use Zitadel\Sdk\Auth\HttpProxy;
use Zitadel\Sdk\Auth\PkceFlow;
use Zitadel\Sdk\Auth\PkceStateCookie;
use Zitadel\Sdk\Auth\TokenValidator;
use Zitadel\Sdk\Config\ZitadelConfig;
use Zitadel\Sdk\Event\ZitadelLoginEvent;
use Zitadel\Sdk\Event\ZitadelLogoutEvent;
use Zitadel\Sdk\Exception\PkceException;

/**
 * Phalcon Micro middleware that owns the complete Zitadel authentication lifecycle.
 *
 * Fires before route matching via `$app->before()`. Returns false to stop the
 * pipeline when the middleware handles the response itself (callback, logout,
 * or protected-route redirect).
 *
 * Registration in `public/index.php`:
 * ```php
 * $app->before(new ZitadelMicroPlugin($config, $validator));
 * ```
 *
 * **Note**: `#[AllowAnonymous]` is NOT supported — Phalcon Micro routes are
 * typically closures and cannot carry PHP attributes. Use `ignoredRoutes` in
 * {@see ZitadelConfig} to exempt specific paths.
 *
 * Access claims in route handlers:
 * ```php
 * $app->get('/dashboard', function () use ($app) {
 *     $claims = $app->getDI()->get('zitadel.claims');
 *     echo "Hello {$claims?->name}";
 * });
 * ```
 */
readonly class ZitadelMicroPlugin implements MiddlewareInterface
{
    /**
     * @param ZitadelConfig  $config    SDK configuration (issuer, cookie secret, route paths).
     * @param TokenValidator $validator JWT validator backed by the shared JWKS cache.
     */
    public function __construct(
        private ZitadelConfig  $config,
        private TokenValidator $validator,
    ) {
    }

    /**
     * Processes the incoming request through the full Zitadel authentication lifecycle.
     *
     * Handles callback and logout paths, validates tokens, and redirects unauthenticated
     * requests to the Zitadel authorization endpoint. Returns false when the response has
     * been sent directly, stopping the Phalcon Micro pipeline.
     *
     * @param Micro $application The Phalcon Micro application instance; provides the DI container.
     * @return bool True to continue routing, false when the response has already been sent.
     */
    #[\Override]
    public function call(Micro $application): bool
    {
        $di      = $application->getDI();
        $request = $di->get('request');
        $path    = '/' . ltrim($request->getURI(true), '/');

        // Reset claims and any stale pending-redirect flag from the previous request.
        // In long-running runtimes (Swoole, RoadRunner) where the DI container is
        // shared across requests, stale state from a previous request must be cleared
        // unconditionally before any logic runs — including paths that short-circuit
        // before a controller is dispatched (proxy, callback, logout).
        $di->set('zitadel.claims', static fn () => null);
        if ($di->has('_zitadel_pending_redirect')) {
            $di->remove('_zitadel_pending_redirect');
        }

        // Handle proxy (before callback/logout — fires before route matching)
        if (HttpProxy::isProxyPath($path, $this->config->proxyPath)) {
            $response = $this->handleProxy($request);
            $di->set('response', $response);
            $response->send();
            $application->stop();
            return false;
        }

        // Handle callback
        if ($path === $this->config->callbackPath) {
            $response = $this->handleCallback($request, $application->getEventsManager());
            $di->set('response', $response);
            $response->send();
            $application->stop();
            return false;
        }

        // Handle logout
        if ($path === $this->config->logoutPath) {
            $response = $this->handleLogout($request, $application->getEventsManager());
            $di->set('response', $response);
            $response->send();
            $application->stop();
            return false;
        }

        // Ignored routes pass through
        if (PkceFlow::matchesRoutes($path, $this->config->ignoredRoutes)) {
            $di->set('zitadel.claims', static fn () => null);
            return true;
        }

        // Extract token (Bearer wins over cookie)
        $bearer = $request->getHeader('Authorization');
        $token  = null;
        if (str_starts_with($bearer, 'Bearer ')) {
            $token = substr($bearer, 7);
        } else {
            $cookie = $_COOKIE['__nextgen_auth'] ?? null;
            if (is_string($cookie) && $cookie !== '') {
                $token = $cookie;
            }
        }

        $claims = $token !== null ? $this->validator->validate((string) $token) : null;

        if ($claims !== null) {
            $di->set('zitadel.claims', static fn () => $claims);
            return true;
        }

        // Protect route
        if ($this->config->protectAll || PkceFlow::matchesRoutes($path, $this->config->protectedRoutes)) {
            $next = $request->getURI();
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

            header($this->buildCookieHeader('__nextgen_pkce', $cookie, 600, $request->isSecure()), false);

            $response = new Response();
            $response->redirect($authUrl, true);
            $di->set('response', $response);
            $response->send();
            $application->stop();
            return false;
        }

        // Public unauthenticated — delete stale cookies
        $di->set('zitadel.claims', static fn () => null);
        foreach (array_keys($_COOKIE) as $name) {
            if (str_starts_with((string) $name, '__nextgen')) {
                header($this->buildCookieHeader((string) $name, '', 0, $request->isSecure()), false);
            }
        }

        return true;
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
                $name           = str_replace('_', '-', substr($key, 5));
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
        // Mirror Next.js/Nuxt behavior: consider X-Forwarded-Proto so that session
        // cookies get the Secure flag even when TLS is terminated at a load balancer.
        $isSecure   = $request->isSecure()
            || strtolower($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https';

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
     * @param Request $request The callback request containing `code` and `state` query params.
     * @return Response A redirect response, or a 400 error response on any validation failure.
     */
    private function handleCallback(Request $request, ?EventsManagerInterface $eventsManager = null): Response
    {
        // Determine Secure flag early — needed for PKCE cookie deletion on every error exit,
        // including the first two paths where the cookie is absent or tampered.
        $secure = $request->isSecure();

        $pkceValue = $_COOKIE['__nextgen_pkce'] ?? null;
        if (!is_string($pkceValue) || $pkceValue === '') {
            header($this->buildCookieHeader('__nextgen_pkce', '', 0, $secure), false);
            return $this->badRequest('Authentication failed — PKCE state cookie missing. Please try signing in again.');
        }

        $pkce = PkceStateCookie::decrypt($pkceValue, $this->config->cookieSecret);
        if ($pkce === null) {
            header($this->buildCookieHeader('__nextgen_pkce', '', 0, $secure), false);
            return $this->badRequest('Authentication failed — PKCE state cookie invalid. Please try signing in again.');
        }

        $state = $request->getQuery('state');
        if (!hash_equals($pkce['state'], (string) $state)) {
            header($this->buildCookieHeader('__nextgen_pkce', '', 0, $secure), false);
            return $this->badRequest('Authentication failed — state parameter mismatch. Please try signing in again.');
        }

        $code = $request->getQuery('code');
        if (!is_string($code) || $code === '') {
            $oauthError = $request->getQuery('error_description') ?? $request->getQuery('error') ?? 'Missing code';
            header($this->buildCookieHeader('__nextgen_pkce', '', 0, $secure), false);
            return $this->badRequest("Authentication failed — {$oauthError}. Please try signing in again.");
        }

        try {
            $tokens = PkceFlow::exchangeCode($this->config, $code, $pkce['verifier']);
        } catch (PkceException) {
            header($this->buildCookieHeader('__nextgen_pkce', '', 0, $secure), false);
            return $this->badRequest('Authentication failed — the login server returned an error. Please try signing in again.');
        }

        $tokenToValidate = PkceFlow::selectToken($tokens);
        if ($tokenToValidate === null) {
            header($this->buildCookieHeader('__nextgen_pkce', '', 0, $secure), false);
            return $this->badRequest('Authentication failed — no usable token in response.');
        }

        $claims = $this->validator->validate($tokenToValidate);
        if ($claims === null) {
            header($this->buildCookieHeader('__nextgen_pkce', '', 0, $secure), false);
            return $this->badRequest('Authentication failed — could not validate the token received from the identity provider.');
        }

        $next   = PkceFlow::sanitizeNext($pkce['next']) ?? $this->config->postLoginRedirect;
        $maxAge = max(0, $claims->exp - time());

        if ($eventsManager !== null) {
            $eventsManager->fire('zitadel:afterLogin', $this, new ZitadelLoginEvent($claims));
        }

        header($this->buildCookieHeader('__nextgen_auth', $tokenToValidate, $maxAge, $secure), false);
        header($this->buildCookieHeader('__nextgen_pkce', '', 0, $secure), false);

        $response = new Response();
        $response->redirect($next, true);

        return $response;
    }

    /**
     * Clears the session cookie and redirects to Zitadel's end-session endpoint.
     *
     * @param Request $request The logout request (scheme is used for the cookie Secure flag).
     * @return Response A redirect response to the OIDC end-session endpoint.
     */
    private function handleLogout(Request $request, ?EventsManagerInterface $eventsManager = null): Response
    {
        if ($eventsManager !== null) {
            $eventsManager->fire('zitadel:afterLogout', $this, new ZitadelLogoutEvent());
        }

        $secure = $request->isSecure();
        header($this->buildCookieHeader('__nextgen_auth', '', 0, $secure), false);

        foreach (array_keys($_COOKIE) as $name) {
            if (str_starts_with((string) $name, '__nextgen') && (string) $name !== '__nextgen_auth') {
                header($this->buildCookieHeader((string) $name, '', 0, $secure), false);
            }
        }

        $params   = http_build_query(['client_id' => $this->config->clientId, 'post_logout_redirect_uri' => $this->config->postLogoutAbsoluteUri()]);
        $response = new Response();
        $response->redirect($this->config->endSessionEndpoint() . '?' . $params, true);

        return $response;
    }

    /**
     * Builds a raw `Set-Cookie` header string for a given cookie name and value.
     *
     * Must be emitted via `header($str, false)` to prevent Phalcon's response headers
     * from overwriting earlier `Set-Cookie` headers in the same response.
     *
     * @param string $name   Cookie name.
     * @param string $value  Cookie value (URL-encoded before inclusion).
     * @param int    $maxAge Max-Age in seconds. Use 0 to delete the cookie.
     * @param bool   $secure Whether to add the `Secure` attribute.
     * @return string A complete `Set-Cookie: ...` header string.
     */
    private function buildCookieHeader(string $name, string $value, int $maxAge, bool $secure): string
    {
        $parts = [
            $name . '=' . urlencode($value),
            'Max-Age=' . $maxAge,
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
