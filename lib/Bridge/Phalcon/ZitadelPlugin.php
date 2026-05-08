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
    ) {}

    /**
     * Fires before the Phalcon router handles the request.
     *
     * Returns false to stop the application when this plugin sends the response
     * (callback, logout, or protected-route redirect). Returning false signals
     * to `index.php` that `handle()` returned false and the response has already
     * been sent or is stored in the DI container.
     */
    public function beforeHandleRequest(Event $event, Application $application): bool
    {
        $di      = $application->getDI();
        $request = $di->get('request');
        $path    = '/' . ltrim($request->getURI(true), '/');

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
            $di->set('zitadel.claims', null);
            return true;
        }

        // Extract token (Bearer wins over cookie)
        $bearer = $request->getHeader('Authorization');
        $token  = null;
        if (str_starts_with($bearer, 'Bearer ')) {
            $token = substr($bearer, 7);
        } elseif ($request->hasCookie('__nextgen_auth')) {
            $token = $request->getCookie('__nextgen_auth');
        }

        $claims = $token !== null ? $this->validator->validate((string) $token) : null;

        if ($claims !== null) {
            $di->set('zitadel.claims', $claims);
            return true;
        }

        // Store pending-protect flag; will check #[AllowAnonymous] at beforeDispatch
        if ($this->config->protectAll || $this->matchesRoutes($path, $this->config->protectedRoutes)) {
            $di->set('_zitadel_pending_redirect', true);
            $di->set('_zitadel_path', $path);
            return true;
        }

        // Public unauthenticated — delete stale cookies
        $di->set('zitadel.claims', null);
        $response = new Response();
        foreach (array_keys($_COOKIE) as $name) {
            if (str_starts_with((string) $name, '__nextgen')) {
                $response->setCookies()->set(
                    (string) $name,
                    '',
                    1,
                    '/',
                    false,
                    null,
                    $request->isSecure()
                );
            }
        }

        return true;
    }

    /**
     * Fires after the dispatcher resolves controller+action, before execution.
     *
     * Checks `#[AllowAnonymous]` when a protected redirect is pending.
     * If anonymous is allowed, clears the pending flag. Otherwise, redirects.
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
                $di->set('zitadel.claims', null);
                return true;
            }

            if ($classRef->hasMethod($actionName) &&
                !empty($classRef->getMethod($actionName)->getAttributes(AllowAnonymous::class))) {
                $di->remove('_zitadel_pending_redirect');
                $di->set('zitadel.claims', null);
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
        $response->redirect($authUrl, true);
        $response->getCookies()->set(
            '__nextgen_pkce',
            $cookie,
            time() + 600,
            '/',
            false,
            null,
            $request->isSecure()
        );
        $di->set('response', $response);
        $response->send();

        // Stop dispatch
        return false;
    }

    private function handleCallback(Request $request, DiInterface $di): Response
    {
        $pkceValue = $request->getCookie('__nextgen_pkce');
        if (!is_string($pkceValue) || $pkceValue === '') {
            return $this->badRequest('Authentication failed — PKCE state cookie missing. Please try signing in again.');
        }

        $pkce = PkceStateCookie::decrypt($pkceValue, $this->config->cookieSecret);
        if ($pkce === null) {
            return $this->badRequest('Authentication failed — PKCE state cookie invalid. Please try signing in again.');
        }

        $state = $request->getQuery('state');
        if ($state !== $pkce['state']) {
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

        $response = new Response();
        $response->redirect($next, true);
        $response->getCookies()->set('__nextgen_auth', $accessToken, time() + $maxAge, '/', false, null, $secure);
        $response->getCookies()->set('__nextgen_pkce', '', 1, '/', false, null, $secure);

        return $response;
    }

    private function handleLogout(Request $request): Response
    {
        $params   = http_build_query(['post_logout_redirect_uri' => $this->config->postLogoutRedirect]);
        $response = new Response();
        $response->redirect($this->config->endSessionEndpoint() . '?' . $params, true);
        $response->getCookies()->set('__nextgen_auth', '', 1, '/', false, null, $request->isSecure());

        return $response;
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
