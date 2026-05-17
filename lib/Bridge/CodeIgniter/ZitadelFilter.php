<?php

declare(strict_types=1);

namespace Zitadel\Sdk\Bridge\CodeIgniter;

use CodeIgniter\Events\Events;
use CodeIgniter\Filters\FilterInterface;
use CodeIgniter\HTTP\IncomingRequest;
use CodeIgniter\HTTP\RequestInterface;
use CodeIgniter\HTTP\ResponseInterface;
use Zitadel\Sdk\Attribute\AllowAnonymous;
use Zitadel\Sdk\Auth\HttpProxy;
use Zitadel\Sdk\Auth\JwksCache;
use Zitadel\Sdk\Auth\PkceFlow;
use Zitadel\Sdk\Auth\PkceStateCookie;
use Zitadel\Sdk\Auth\TokenValidator;
use Zitadel\Sdk\Bridge\CodeIgniter\Config\Zitadel as ZitadelCIConfig;
use Zitadel\Sdk\Config\ZitadelConfig;
use Zitadel\Sdk\Event\ZitadelLoginEvent;
use Zitadel\Sdk\Event\ZitadelLogoutEvent;
use Zitadel\Sdk\Exception\PkceException;

/**
 * Post-routing CI4 filter that enforces authentication on every matched route.
 *
 * Registered in `$globals['before']` via {@see \Zitadel\Sdk\Config\Registrar},
 * this filter runs after CI4's router has resolved the controller. It handles the
 * full authentication pipeline:
 *
 * - Ignored routes are passed through without any token check.
 * - A `Bearer` header or `__nextgen_auth` cookie is validated as a JWT.
 * - `#[AllowAnonymous]` on the matched controller class or action allows access
 *   without a valid token (requires a resolved controller, hence post-routing only).
 * - Protected routes (or all routes when `$protectAll` is `true`) redirect to
 *   Zitadel's authorization endpoint via the PKCE flow.
 *
 * The SDK's own HTTP paths (proxy, callback, logout) are handled before routing by
 * {@see ZitadelPreFilter} and never reach this filter.
 *
 * After successful validation, authenticated claims are stored in
 * {@see ZitadelHolder} for controller access via `ZitadelHolder::claims()`.
 *
 * This filter is completely stateless — no instance variables are mutated between
 * calls. It is safe for use in persistent PHP processes (FrankenPHP, Swoole,
 * RoadRunner) without any per-request reset logic.
 */
class ZitadelFilter implements FilterInterface
{
    protected ZitadelConfig  $config;
    protected TokenValidator $validator;

    /**
     * Accepts optional explicit dependencies for testing or advanced DI usage.
     *
     * When omitted, the filter self-configures: it calls `config('Zitadel')` to
     * obtain the application's {@see ZitadelCIConfig} instance (CI4 resolves the
     * developer's `app/Config/Zitadel.php` override first, then falls back to the
     * SDK base class), maps every property onto a {@see ZitadelConfig} value object,
     * and creates a default {@see TokenValidator} backed by a {@see JwksCache}.
     *
     * This means no `Services.php` factories are required for standard usage.
     */
    public function __construct(
        ?ZitadelConfig  $config    = null,
        ?TokenValidator $validator = null,
    ) {
        if ($config === null) {
            /** @var ZitadelCIConfig $cfg */
            $cfg    = config('Zitadel');
            $config = new ZitadelConfig(
                issuerUrl:          $cfg->issuerUrl,
                clientId:           $cfg->clientId,
                redirectUri:        $cfg->redirectUri,
                cookieSecret:       $cfg->cookieSecret,
                callbackPath:       $cfg->callbackPath,
                logoutPath:         $cfg->logoutPath,
                proxyPath:          $cfg->proxyPath,
                postLoginRedirect:  $cfg->postLoginRedirect,
                postLogoutRedirect: $cfg->postLogoutRedirect,
                protectAll:         $cfg->protectAll,
                ignoredRoutes:      $cfg->ignoredRoutes,
                protectedRoutes:    $cfg->protectedRoutes,
                jwksPath:           $cfg->jwksPath,
                authorizationPath:  $cfg->authorizationPath,
                tokenPath:          $cfg->tokenPath,
                endSessionPath:     $cfg->endSessionPath,
                scopes:             $cfg->scopes,
                allowedAlgorithms:  $cfg->allowedAlgorithms,
                allowedTokenTypes:  $cfg->allowedTokenTypes,
                audience:           $cfg->audience,
                clockSkewSeconds:     $cfg->clockSkewSeconds,
                jwksTtlSeconds:       $cfg->jwksTtlSeconds,
                httpTimeoutSeconds:   $cfg->httpTimeoutSeconds,
                pkceCookieTtlSeconds: $cfg->pkceCookieTtlSeconds,
                trustXForwardedProto: $cfg->trustXForwardedProto,
            );
        }
        $this->config    = $config;
        $this->validator = $validator ?? new TokenValidator($this->config, new JwksCache());
    }

    /**
     * Enforces authentication after the router has resolved the controller.
     *
     * This method is called by CI4 for every request whose URI matches a registered
     * route. SDK-owned paths (proxy, callback, logout) are handled before routing by
     * {@see ZitadelPreFilter} and never arrive here.
     *
     * @param RequestInterface  $request   The incoming HTTP request.
     * @param array<mixed>|null $arguments Unused.
     * @return ResponseInterface|null Redirect to authorise, or null to continue.
     */
    #[\Override]
    public function before(RequestInterface $request, $arguments = null): ?ResponseInterface
    {
        // Reset on every call so stale claims from a previous request on the same
        // worker cannot leak into this one.
        ZitadelHolder::set(null);

        if (!$request instanceof IncomingRequest) {
            return null;
        }

        $path = '/' . ltrim($request->getPath(), '/');

        // Ignored routes pass through without any token check.
        if (PkceFlow::matchesRoutes($path, $this->config->ignoredRoutes)) {
            return null;
        }

        // Extract token — Bearer header wins over cookie.
        $bearer = $request->getHeaderLine('Authorization');
        $token  = null;
        if (preg_match('/^Bearer\s+(\S+)$/i', $bearer, $m)) {
            $token = $m[1];
        } elseif (is_string($cookie = $request->getCookie('__nextgen_auth')) && $cookie !== '') {
            $token = $cookie;
        }

        $claims = $token !== null ? $this->validator->validate((string) $token) : null;

        if ($claims !== null) {
            ZitadelHolder::set($claims);
            return null;
        }

        // #[AllowAnonymous] requires a resolved controller — only available post-routing.
        if ($this->hasAllowAnonymous()) {
            return null;
        }

        // Redirect unauthenticated requests on protected routes.
        if ($this->config->protectAll || PkceFlow::matchesRoutes($path, $this->config->protectedRoutes)) {
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
                $this->config->pkceCookieTtlSeconds,
                '',
                '/',
                '',
                $request->isSecure(),
                true,
                'Lax'
            );

            return $response;
        }

        // Public unauthenticated request — scrub any stale SDK cookies.
        $response = service('response');
        $secure   = $request->isSecure();
        foreach (array_keys((array) $request->getCookie()) as $name) {
            $name = (string) $name;
            if (!str_starts_with($name, '__nextgen')) {
                continue;
            }

            // Guard against cookie-name injection (RFC 6265 §4.1 token chars only).
            if (preg_match('/^[A-Za-z0-9_\-]+$/', $name) !== 1) {
                continue;
            }

            $response->deleteCookie($name, '', '/', '', $secure);
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
     * Reverse-proxies a `/__nextgen/*` request to the upstream auth backend.
     *
     * Strips hop-by-hop and internal headers in both directions, appends
     * `REMOTE_ADDR` to the `X-Forwarded-For` chain, and upgrades `__nextgen*`
     * session cookies to `Secure` when the client connection is HTTPS.
     * Multiple `Set-Cookie` headers are emitted via `header(..., false)` since
     * CI4's `Response::setHeader()` uses replace semantics for repeated names.
     * Returns a 502 Bad Gateway response on cURL failure.
     *
     * @param IncomingRequest $request The incoming proxy request.
     * @return ResponseInterface The upstream response (or 502 on failure).
     */
    protected function handleProxy(IncomingRequest $request): ResponseInterface
    {
        $proxyPath = rtrim($this->config->proxyPath, '/');
        $suffix    = substr('/' . ltrim($request->getPath(), '/'), strlen($proxyPath));

        if (str_contains($suffix, '..')) {
            return service('response')
                ->setStatusCode(400)
                ->setContentType('text/plain; charset=utf-8')
                ->setBody('Bad Request');
        }

        $query  = $request->getUri()->getQuery();
        $target = $this->config->issuerUrl . $suffix . ($query !== '' ? '?' . $query : '');

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
        $host       = $_SERVER['HTTP_HOST'] ?? $request->getUri()->getHost();
        $proto      = $request->getUri()->getScheme();
        $isSecure   = $request->isSecure()
            || ($this->config->trustXForwardedProto
                && strtolower($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https');

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
            return service('response')
                ->setStatusCode(502)
                ->setContentType('text/plain; charset=utf-8')
                ->setBody('Bad Gateway');
        }

        $response = service('response')->setStatusCode($result['status']);

        foreach ($result['headers'] as $name => $values) {
            $response->setHeader($name, implode(', ', $values));
        }

        foreach ($result['setCookies'] as $cookie) {
            header('Set-Cookie: ' . HttpProxy::upgradeSessionCookie($cookie, $isSecure), false);
        }

        $response->setBody($result['body']);

        return $response;
    }

    /**
     * Validates the PKCE state cookie, exchanges the authorization code, validates the
     * resulting access token, and redirects to the originally requested path.
     *
     * @param IncomingRequest $request The callback request containing `code` and `state` query params.
     * @return ResponseInterface Redirect with `__nextgen_auth` cookie set, or a 400 error response.
     */
    protected function handleCallback(IncomingRequest $request): ResponseInterface
    {
        // Capture Secure flag early — needed for cookie deletion on every exit path.
        $secure = $request->isSecure();

        $pkceValue = $request->getCookie('__nextgen_pkce');
        if (!is_string($pkceValue) || $pkceValue === '') {
            $response = $this->badRequest('Authentication failed — PKCE state cookie missing. Please try signing in again.');
            $response->deleteCookie('__nextgen_pkce', '', '/', '', $secure);
            return $response;
        }

        $pkce = PkceStateCookie::decrypt($pkceValue, $this->config->cookieSecret);
        if ($pkce === null) {
            $response = $this->badRequest('Authentication failed — PKCE state cookie invalid. Please try signing in again.');
            $response->deleteCookie('__nextgen_pkce', '', '/', '', $secure);
            return $response;
        }

        $state = $request->getGet('state');
        if (!hash_equals($pkce['state'], (string) $state)) {
            $response = $this->badRequest('Authentication failed — state parameter mismatch. Please try signing in again.');
            $response->deleteCookie('__nextgen_pkce', '', '/', '', $secure);
            return $response;
        }

        $code = $request->getGet('code');
        if (!is_string($code) || $code === '') {
            // Log the OAuth error server-side only — do not reflect it back to the
            // browser, as an attacker can craft a callback URL with an arbitrary
            // error_description to create a convincing phishing page (CWE-116).
            $oauthError = $request->getGet('error_description') ?? $request->getGet('error') ?? 'no error param';
            log_message('error', '[zitadel] Callback missing code: ' . $oauthError);
            $response = $this->badRequest('Authentication failed — authorization code missing. Please try signing in again.');
            $response->deleteCookie('__nextgen_pkce', '', '/', '', $secure);
            return $response;
        }

        try {
            $tokens = PkceFlow::exchangeCode($this->config, $code, $pkce['verifier']);
        } catch (PkceException) {
            $response = $this->badRequest('Authentication failed — the login server returned an error. Please try signing in again.');
            $response->deleteCookie('__nextgen_pkce', '', '/', '', $secure);
            return $response;
        }

        $tokenToValidate = PkceFlow::selectToken($tokens);
        if ($tokenToValidate === null) {
            $response = $this->badRequest('Authentication failed — no usable token in response.');
            $response->deleteCookie('__nextgen_pkce', '', '/', '', $secure);
            return $response;
        }

        $claims = $this->validator->validate($tokenToValidate);
        if ($claims === null) {
            $response = $this->badRequest('Authentication failed — could not validate the token received from the identity provider.');
            $response->deleteCookie('__nextgen_pkce', '', '/', '', $secure);
            return $response;
        }

        // Defence-in-depth: confirm the token is header-safe before writing the cookie.
        if (preg_match('/^[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+$/', $tokenToValidate) !== 1) {
            $response = $this->badRequest('Authentication failed — token contains unsafe characters.');
            $response->deleteCookie('__nextgen_pkce', '', '/', '', $secure);
            return $response;
        }

        $next   = PkceFlow::sanitizeNext($pkce['next']) ?? $this->config->postLoginRedirect;
        $maxAge = max(0, $claims->exp - time());

        Events::trigger('zitadel_login', new ZitadelLoginEvent($claims));

        $response = response()->redirect($next);
        $response->setCookie('__nextgen_auth', $tokenToValidate, $maxAge, '', '/', '', $secure, true, 'Lax');
        $response->deleteCookie('__nextgen_pkce', '', '/', '', $secure);

        return $response;
    }

    /**
     * Clears the session cookie and redirects to Zitadel's end-session endpoint.
     *
     * @param IncomingRequest $request The logout request (used to determine scheme for cookie flags).
     * @return ResponseInterface Redirect to the OIDC end-session endpoint with the auth cookie deleted.
     */
    protected function handleLogout(IncomingRequest $request): ResponseInterface
    {
        Events::trigger('zitadel_logout', new ZitadelLogoutEvent());

        $params   = http_build_query(['client_id' => $this->config->clientId, 'post_logout_redirect_uri' => $this->config->postLogoutAbsoluteUri()]);
        $response = response()->redirect($this->config->endSessionEndpoint() . '?' . $params);
        $response->setCookie('__nextgen_auth', '', 0, '', '/', '', $request->isSecure(), true, 'Lax');

        foreach (array_keys((array) $request->getCookie()) as $name) {
            $name = (string) $name;
            if (!str_starts_with($name, '__nextgen') || $name === '__nextgen_auth') {
                continue;
            }

            // Guard against cookie-name injection (RFC 6265 §4.1 token chars only).
            if (preg_match('/^[A-Za-z0-9_\-]+$/', $name) !== 1) {
                continue;
            }

            $response->deleteCookie($name, '', '/', '', $request->isSecure());
        }

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
            $router          = service('router');
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
     * Builds a 400 Bad Request HTML error response with a human-readable message.
     *
     * @param string $message The authentication error description shown to the user.
     * @return ResponseInterface A 400 response with `Content-Type: text/html; charset=utf-8`.
     */
    protected function badRequest(string $message): ResponseInterface
    {
        $html = '<!DOCTYPE html><html><head><title>Authentication Error</title></head><body>'
            . '<h1>Authentication Error</h1><p>' . htmlspecialchars($message, ENT_QUOTES, 'UTF-8') . '</p>'
            . '<p><a href="/">Go to homepage</a></p>'
            . '</body></html>';

        return service('response')
            ->setStatusCode(400)
            ->setContentType('text/html; charset=utf-8')
            ->setBody($html);
    }
}
