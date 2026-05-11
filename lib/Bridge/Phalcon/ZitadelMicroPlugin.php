<?php

declare(strict_types=1);

namespace Zitadel\Sdk\Bridge\Phalcon;

use Phalcon\Http\Request;
use Phalcon\Http\Response;
use Phalcon\Mvc\Micro;
use Phalcon\Mvc\Micro\MiddlewareInterface;
use Zitadel\Sdk\Auth\PkceFlow;
use Zitadel\Sdk\Auth\PkceStateCookie;
use Zitadel\Sdk\Auth\TokenValidator;
use Zitadel\Sdk\Config\ZitadelConfig;
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

        // Handle callback
        if ($path === $this->config->callbackPath) {
            $response = $this->handleCallback($request);
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

        // Protect route
        if ($this->config->protectAll || $this->matchesRoutes($path, $this->config->protectedRoutes)) {
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

            header($this->buildCookieHeader('__nextgen_pkce', $cookie, time() + 600, $request->isSecure()), false);

            $response = new Response();
            $response->redirect($authUrl, true);
            $di->set('response', $response);
            $response->send();
            return false;
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
     * Validates the PKCE state cookie, exchanges the authorization code, and redirects
     * to the originally requested path with the session cookie set.
     *
     * @param Request $request The callback request containing `code` and `state` query params.
     * @return Response A redirect response, or a 400 error response on any validation failure.
     */
    private function handleCallback(Request $request): Response
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

        header($this->buildCookieHeader('__nextgen_auth', $tokenToValidate, time() + $maxAge, $secure), false);
        header($this->buildCookieHeader('__nextgen_pkce', '', 1, $secure), false);

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
    private function handleLogout(Request $request): Response
    {
        header($this->buildCookieHeader('__nextgen_auth', '', 1, $request->isSecure()), false);

        $params   = http_build_query(['client_id' => $this->config->clientId, 'post_logout_redirect_uri' => $this->config->postLogoutAbsoluteUri()]);
        $response = new Response();
        $response->redirect($this->config->endSessionEndpoint() . '?' . $params, true);

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
     * Must be emitted via `header($str, false)` to prevent Phalcon's response headers
     * from overwriting earlier `Set-Cookie` headers in the same response.
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
            urlencode($name) . '=' . urlencode($value),
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
