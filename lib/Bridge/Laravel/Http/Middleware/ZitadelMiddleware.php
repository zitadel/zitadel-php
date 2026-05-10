<?php

declare(strict_types=1);

namespace Zitadel\Sdk\Bridge\Laravel\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Symfony\Component\HttpFoundation\Response as SymfonyResponse;
use Zitadel\Sdk\Attribute\AllowAnonymous;
use Zitadel\Sdk\Auth\PkceFlow;
use Zitadel\Sdk\Auth\PkceStateCookie;
use Zitadel\Sdk\Auth\TokenValidator;
use Zitadel\Sdk\Config\ZitadelConfig;

/**
 * Illuminate middleware registered in the `web` group.
 *
 * Runs after routing (web group, not global) so that:
 * - `$request->route()` is available for `#[AllowAnonymous]` reflection
 * - Callback and logout are handled by dedicated controllers
 *
 * This middleware is NOT responsible for callback or logout — those are routed
 * to {@see \Zitadel\Sdk\Bridge\Laravel\Http\Controllers\CallbackController} and
 * {@see \Zitadel\Sdk\Bridge\Laravel\Http\Controllers\LogoutController}.
 *
 * Route protection is controlled via {@see ZitadelConfig::$protectedRoutes} and
 * {@see ZitadelConfig::$protectAll}. Use `->withoutMiddleware(static::class)` on
 * individual routes or `#[AllowAnonymous]` on controller methods to opt out.
 */
readonly class ZitadelMiddleware
{
    public function __construct(
        private ZitadelConfig  $config,
        private TokenValidator $validator,
    ) {
    }

    /**
     * Processes an incoming request through the Zitadel authentication lifecycle.
     *
     * Ignored routes pass through immediately. Otherwise, extracts a Bearer token or
     * `__nextgen_auth` cookie, validates it, and either attaches claims to the request
     * or redirects to Zitadel for login. Public unauthenticated requests have stale
     * `__nextgen*` cookies cleaned up before the response is returned.
     *
     * @param Request $request The incoming HTTP request.
     * @param Closure $next    The next middleware handler in the pipeline.
     * @return SymfonyResponse The response — either from the next handler or a redirect.
     */
    public function handle(Request $request, Closure $next): SymfonyResponse
    {
        $path = $request->path();
        $path = str_starts_with($path, '/') ? $path : '/' . $path;

        // Ignored routes pass through immediately
        if ($this->matchesRoutes($path, $this->config->ignoredRoutes)) {
            $request->attributes->set('zitadel.claims', null);

            return $next($request);
        }

        // Extract token (Bearer wins over cookie)
        $token  = $request->bearerToken() ?? ($request->cookie('__nextgen_auth') ?: null);
        $claims = $token !== null ? $this->validator->validate((string) $token) : null;

        if ($claims !== null) {
            $request->attributes->set('zitadel.claims', $claims);

            return $next($request);
        }

        // Check #[AllowAnonymous] on the resolved controller method or class
        if ($this->hasAllowAnonymous($request)) {
            $request->attributes->set('zitadel.claims', null);

            return $next($request);
        }

        // Protect route
        if ($this->config->protectAll || $this->matchesRoutes($path, $this->config->protectedRoutes)) {
            $verifier  = PkceFlow::generateCodeVerifier();
            $state     = PkceFlow::generateState();
            $challenge = PkceFlow::generateCodeChallenge($verifier);
            $authUrl   = PkceFlow::buildAuthorizationUrl($this->config, $challenge, $state);

            $returnTo = $request->getRequestUri();
            $cookie   = PkceStateCookie::encrypt(
                $verifier,
                $state,
                $returnTo,
                $this->config->cookieSecret
            );

            return redirect($authUrl)
                ->cookie(
                    '__nextgen_pkce',
                    $cookie,
                    10,
                    '/',
                    null,
                    $request->isSecure(),
                    true,
                    false,
                    'lax'
                );
        }

        // Public unauthenticated
        $request->attributes->set('zitadel.claims', null);
        $response = $next($request);

        // Delete stale __nextgen* cookies
        foreach ($request->cookies->keys() as $name) {
            if (str_starts_with((string) $name, '__nextgen')) {
                $response->headers->setCookie(\Symfony\Component\HttpFoundation\Cookie::create(
                    (string) $name,
                    '',
                    1,
                    '/',
                    null,
                    $request->isSecure(),
                    true,
                    false,
                    'lax'
                ));
            }
        }

        return $response;
    }

    /**
     * Returns true when the matched controller class or action method carries
     * a {@see \Zitadel\Sdk\Attribute\AllowAnonymous} attribute.
     *
     * @param Request $request The current request; used to retrieve the resolved route.
     * @return bool True if anonymous access is permitted for the matched route.
     */
    private function hasAllowAnonymous(Request $request): bool
    {
        $route = $request->route();
        if ($route === null) {
            return false;
        }

        $controllerClass = $route->getControllerClass();
        $actionMethod    = $route->getActionMethod();

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
}
