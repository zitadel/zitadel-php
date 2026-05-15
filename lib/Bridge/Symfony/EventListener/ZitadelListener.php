<?php

declare(strict_types=1);

namespace Zitadel\Sdk\Bridge\Symfony\EventListener;

use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\ControllerEvent;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\KernelEvents;
use Zitadel\Sdk\Attribute\AllowAnonymous;
use Zitadel\Sdk\Auth\HttpProxy;
use Zitadel\Sdk\Auth\PkceFlow;
use Zitadel\Sdk\Auth\PkceStateCookie;
use Zitadel\Sdk\Auth\TokenValidator;
use Zitadel\Sdk\Config\ZitadelConfig;
use Zitadel\Sdk\Exception\PkceException;

/**
 * Symfony event subscriber that owns the complete Zitadel authentication lifecycle.
 *
 * Subscribes to three kernel events:
 *
 * **`KernelEvents::REQUEST` (priority 33)** — fires before RouterListener (32).
 * Handles:
 * - Callback path: validates PKCE state, exchanges code, validates token, sets cookie, redirects
 * - Logout path: clears cookie, redirects to Zitadel end-session endpoint
 * - Ignored routes: passes through without token check
 * - Token extraction (Bearer > cookie) and validation
 * - Protected route redirect to Zitadel authorization endpoint
 * - Public unauthenticated: sets `zitadel.claims` to null, marks request for stale-cookie cleanup
 *
 * **`KernelEvents::CONTROLLER` (priority 0)** — fires after routing resolves the controller.
 * Checks `#[AllowAnonymous]` on the resolved controller method or class. If found and the
 * request was marked as protected-but-unauthenticated, clears the pending redirect flag
 * so the request is passed through as public.
 *
 * **`KernelEvents::RESPONSE` (priority 0)** — fires after the controller produces a response.
 * Deletes stale `__nextgen*` cookies on public unauthenticated responses.
 */
readonly class ZitadelListener implements EventSubscriberInterface
{
    private const string PENDING_REDIRECT_ATTR    = '_zitadel_pending_redirect';
    private const string CLEAR_STALE_COOKIES_ATTR = '_zitadel_clear_stale_cookies';

    public function __construct(
        private ZitadelConfig  $config,
        private TokenValidator $validator,
    ) {
    }

    /**
     * Returns the kernel events this subscriber listens to.
     *
     * @return array<string, array{string, int}> Map of event name → [method, priority].
     */
    #[\Override]
    public static function getSubscribedEvents(): array
    {
        return [
            KernelEvents::REQUEST    => ['onKernelRequest', 33],
            KernelEvents::CONTROLLER => ['onKernelController', 0],
            KernelEvents::RESPONSE   => ['onKernelResponse', 0],
        ];
    }

    /**
     * Handles the kernel request event (priority 33 — fires before RouterListener).
     *
     * Processes callback and logout paths, validates tokens, and either sets
     * `zitadel.claims` on the request or marks it for an #[AllowAnonymous] check
     * at the controller event.
     *
     * @param RequestEvent $event The kernel request event.
     */
    public function onKernelRequest(RequestEvent $event): void
    {
        if (!$event->isMainRequest()) {
            return;
        }

        $request = $event->getRequest();
        $path    = '/' . ltrim($request->getPathInfo(), '/');

        // Handle proxy (before callback/logout — fires before routing so any path is reachable)
        if (HttpProxy::isProxyPath($path, $this->config->proxyPath)) {
            $event->setResponse($this->handleProxy($request));
            return;
        }

        // Handle callback
        if ($path === $this->config->callbackPath) {
            $event->setResponse($this->handleCallback($request));
            return;
        }

        // Handle logout
        if ($path === $this->config->logoutPath) {
            $event->setResponse($this->handleLogout($request));
            return;
        }

        // Ignored routes pass through
        if ($this->matchesRoutes($path, $this->config->ignoredRoutes)) {
            $request->attributes->set('zitadel.claims', null);
            return;
        }

        // Extract token (Bearer wins over cookie)
        $bearer = $request->headers->get('Authorization');
        $token  = null;
        if ($bearer !== null && str_starts_with($bearer, 'Bearer ')) {
            $token = substr($bearer, 7);
        } elseif ($request->cookies->has('__nextgen_auth')) {
            $token = $request->cookies->get('__nextgen_auth');
        }

        $claims = $token !== null ? $this->validator->validate((string) $token) : null;

        if ($claims !== null) {
            $request->attributes->set('zitadel.claims', $claims);
            return;
        }

        // Mark for #[AllowAnonymous] check at CONTROLLER event
        if ($this->config->protectAll || $this->matchesRoutes($path, $this->config->protectedRoutes)) {
            $request->attributes->set(self::PENDING_REDIRECT_ATTR, true);
            return;
        }

        // Public unauthenticated — mark for stale cookie cleanup at RESPONSE event
        $request->attributes->set('zitadel.claims', null);
        $request->attributes->set(self::CLEAR_STALE_COOKIES_ATTR, true);
    }

    /**
     * Handles the kernel controller event (priority 0 — fires after routing).
     *
     * Checks for `#[AllowAnonymous]` on the resolved controller. If found, clears
     * the pending-redirect flag so the request passes through as public. Otherwise,
     * performs the PKCE redirect.
     *
     * @param ControllerEvent $event The kernel controller event.
     */
    public function onKernelController(ControllerEvent $event): void
    {
        if (!$event->isMainRequest()) {
            return;
        }

        $request = $event->getRequest();

        if (!$request->attributes->get(self::PENDING_REDIRECT_ATTR, false)) {
            return;
        }

        if ($this->controllerHasAllowAnonymous($event->getController())) {
            $request->attributes->remove(self::PENDING_REDIRECT_ATTR);
            $request->attributes->set('zitadel.claims', null);
            return;
        }

        // Proceed with PKCE redirect
        $request->attributes->remove(self::PENDING_REDIRECT_ATTR);
        $verifier  = PkceFlow::generateCodeVerifier();
        $state     = PkceFlow::generateState();
        $challenge = PkceFlow::generateCodeChallenge($verifier);
        $authUrl   = PkceFlow::buildAuthorizationUrl($this->config, $challenge, $state);
        $next      = $request->getRequestUri();
        $cookie    = PkceStateCookie::encrypt(
            $verifier,
            $state,
            $next,
            $this->config->cookieSecret
        );

        $response = new RedirectResponse($authUrl);
        $response->headers->setCookie(new Cookie(
            '__nextgen_pkce',
            $cookie,
            time() + 600,
            '/',
            null,
            $request->isSecure(),
            true,
            false,
            'lax'
        ));

        // ControllerEvent has no setResponse(); wrap the controller so the kernel returns this response.
        $event->setController(static fn () => $response);
    }

    /**
     * Handles the kernel response event (priority 0).
     *
     * Deletes stale `__nextgen*` cookies on public unauthenticated responses
     * by setting them to expire in the past.
     *
     * @param ResponseEvent $event The kernel response event.
     */
    public function onKernelResponse(ResponseEvent $event): void
    {
        if (!$event->isMainRequest()) {
            return;
        }

        if (!$event->getRequest()->attributes->get(self::CLEAR_STALE_COOKIES_ATTR, false)) {
            return;
        }

        $response = $event->getResponse();
        $secure   = $event->getRequest()->isSecure();

        foreach ($event->getRequest()->cookies->keys() as $name) {
            if (str_starts_with((string) $name, '__nextgen')) {
                $response->headers->setCookie(new Cookie(
                    (string) $name,
                    '',
                    1,
                    '/',
                    null,
                    $secure,
                    true,
                    false,
                    'lax'
                ));
            }
        }
    }

    /**
     * Reverse-proxies a `/__nextgen/*` request to the upstream auth backend.
     *
     * Strips hop-by-hop and internal headers in both directions, appends
     * `REMOTE_ADDR` to the `X-Forwarded-For` chain, and upgrades `__nextgen*`
     * session cookies to `Secure` when the client connection is HTTPS. Returns
     * a 502 Bad Gateway response on cURL failure.
     *
     * @param \Symfony\Component\HttpFoundation\Request $request The incoming proxy request.
     * @return Response The upstream response (or 502 on failure).
     */
    private function handleProxy(\Symfony\Component\HttpFoundation\Request $request): Response
    {
        $proxyPath = rtrim($this->config->proxyPath, '/');
        $suffix    = substr($request->getPathInfo(), strlen($proxyPath));
        $query     = $request->getQueryString();
        $target    = $this->config->issuerUrl . $suffix . ($query !== null && $query !== '' ? '?' . $query : '');

        $headers = [];
        foreach ($request->headers->all() as $name => $values) {
            $headers[$name] = implode(', ', $values);
        }

        $method     = $request->getMethod();
        $hasBody    = !in_array(strtoupper($method), ['GET', 'HEAD'], true);
        $body       = $hasBody ? (string) $request->getContent() : '';
        $remoteAddr = (string) ($request->server->get('REMOTE_ADDR') ?? '');
        $host       = (string) ($request->headers->get('Host') ?: $request->getHost());
        $proto      = $request->getScheme();
        // Mirror Next.js/Nuxt behavior: consider X-Forwarded-Proto so that session
        // cookies get the Secure flag even when TLS is terminated at a load balancer.
        $isSecure   = $request->isSecure()
            || strtolower((string) ($request->headers->get('X-Forwarded-Proto') ?? '')) === 'https';

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
            return new Response('Bad Gateway', 502, ['Content-Type' => 'text/plain; charset=utf-8']);
        }

        $response = new Response($result['body'], $result['status']);

        foreach ($result['headers'] as $name => $values) {
            foreach ($values as $value) {
                $response->headers->set($name, $value, false);
            }
        }

        foreach ($result['setCookies'] as $cookie) {
            $response->headers->set(
                'Set-Cookie',
                HttpProxy::upgradeSessionCookie($cookie, $isSecure),
                false,
            );
        }

        return $response;
    }

    /**
     * Validates the PKCE state cookie, exchanges the authorization code, and redirects
     * to the originally requested path with the session cookie set.
     *
     * @param \Symfony\Component\HttpFoundation\Request $request The callback request.
     * @return Response A redirect response on success, or a 400 error response on failure.
     */
    private function handleCallback(\Symfony\Component\HttpFoundation\Request $request): Response
    {
        $pkceValue = $request->cookies->get('__nextgen_pkce');
        if (!is_string($pkceValue) || $pkceValue === '') {
            return $this->badRequest('Authentication failed — PKCE state cookie missing. Please try signing in again.');
        }

        $pkce = PkceStateCookie::decrypt($pkceValue, $this->config->cookieSecret);
        if ($pkce === null) {
            return $this->badRequest('Authentication failed — PKCE state cookie invalid. Please try signing in again.');
        }

        $state = $request->query->get('state');
        if (!hash_equals($pkce['state'], (string) $state)) {
            return $this->badRequest('Authentication failed — state parameter mismatch. Please try signing in again.');
        }

        $code = $request->query->get('code');
        if (!is_string($code) || $code === '') {
            $oauthError = $request->query->get('error_description') ?? $request->query->get('error') ?? 'Missing code';
            return $this->badRequest("Authentication failed — {$oauthError}. Please try signing in again.");
        }

        try {
            $tokens = PkceFlow::exchangeCode($this->config, $code, $pkce['verifier']);
        } catch (PkceException $e) {
            return $this->badRequest('Authentication failed — the login server returned an error. Please try signing in again.');
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

        $response = new RedirectResponse($next);
        $response->headers->setCookie(new Cookie(
            '__nextgen_auth',
            $tokenToValidate,
            time() + $maxAge,
            '/',
            null,
            $secure,
            true,
            false,
            'lax'
        ));
        $response->headers->setCookie(new Cookie(
            '__nextgen_pkce',
            '',
            1,
            '/',
            null,
            $secure,
            true,
            false,
            'lax'
        ));

        return $response;
    }

    /**
     * Clears the session cookie and redirects to Zitadel's end-session endpoint.
     *
     * @param \Symfony\Component\HttpFoundation\Request $request The logout request.
     * @return Response A redirect response to the OIDC end-session endpoint.
     */
    private function handleLogout(\Symfony\Component\HttpFoundation\Request $request): Response
    {
        $params   = http_build_query(['client_id' => $this->config->clientId, 'post_logout_redirect_uri' => $this->config->postLogoutAbsoluteUri()]);
        $response = new RedirectResponse($this->config->endSessionEndpoint() . '?' . $params);
        $response->headers->setCookie(new Cookie(
            '__nextgen_auth',
            '',
            1,
            '/',
            null,
            $request->isSecure(),
            true,
            false,
            'lax'
        ));

        return $response;
    }

    /**
     * Returns true when any resolved form of `$controller` carries a
     * {@see \Zitadel\Sdk\Attribute\AllowAnonymous} attribute.
     *
     * Supports all Symfony controller forms: `[$object, 'method']`, invokable objects,
     * and `'ClassName::method'` strings.
     *
     * @param mixed $controller The resolved controller callable.
     * @return bool True if the controller or its method has the AllowAnonymous attribute.
     */
    private function controllerHasAllowAnonymous(mixed $controller): bool
    {
        if (is_array($controller) && count($controller) === 2) {
            [$object, $method] = $controller;
            $classRef = new \ReflectionClass($object);

            if (!empty($classRef->getAttributes(AllowAnonymous::class))) {
                return true;
            }

            if (is_string($method) && $classRef->hasMethod($method)) {
                return !empty($classRef->getMethod($method)->getAttributes(AllowAnonymous::class));
            }

            return false;
        }

        if (is_object($controller)) {
            $classRef = new \ReflectionClass($controller);

            if (!empty($classRef->getAttributes(AllowAnonymous::class))) {
                return true;
            }

            if ($classRef->hasMethod('__invoke')) {
                return !empty($classRef->getMethod('__invoke')->getAttributes(AllowAnonymous::class));
            }
        }

        if (is_string($controller) && str_contains($controller, '::')) {
            [$class, $method] = explode('::', $controller, 2);
            if (class_exists($class)) {
                $classRef = new \ReflectionClass($class);
                if (!empty($classRef->getAttributes(AllowAnonymous::class))) {
                    return true;
                }
                if ($classRef->hasMethod($method)) {
                    return !empty($classRef->getMethod($method)->getAttributes(AllowAnonymous::class));
                }
            }
        }

        return false;
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
     * @param string $next The candidate redirect path from the PKCE state cookie.
     * @return string|null The sanitized path, or null if the input is unsafe.
     */
    private function sanitizeNext(string $next): ?string
    {
        if (!str_starts_with($next, '/') || str_starts_with($next, '//')) {
            return null;
        }

        // Reject paths that decode to a protocol-relative URL.
        // A raw path of "/%2F/evil.com" starts with "/" and passes the literal
        // "//" check, but decodes to "//evil.com" — an open redirect.
        if (str_starts_with(rawurldecode($next), '//')) {
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
     * @return Response A 400 response with `Content-Type: text/html; charset=utf-8`.
     */
    private function badRequest(string $message): Response
    {
        $html = '<!DOCTYPE html><html><head><title>Authentication Error</title></head><body>'
            . '<h1>Authentication Error</h1><p>' . htmlspecialchars($message, ENT_QUOTES, 'UTF-8') . '</p>'
            . '<p><a href="javascript:history.back()">Go back</a></p>'
            . '</body></html>';

        return new Response($html, 400, ['Content-Type' => 'text/html; charset=utf-8']);
    }
}
