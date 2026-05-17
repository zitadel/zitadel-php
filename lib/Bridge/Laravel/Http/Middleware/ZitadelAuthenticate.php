<?php

declare(strict_types=1);

namespace Zitadel\Sdk\Bridge\Laravel\Http\Middleware;

use Closure;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Per-route authentication middleware for the `zitadel` guard.
 *
 * Registered as the `zitadel.auth` middleware alias by
 * {@see \Zitadel\Sdk\Bridge\Laravel\ZitadelServiceProvider}, mirroring the
 * pattern used by `tymon/jwt-auth` (`jwt.auth`) and `laravel/sanctum`.
 *
 * Use this on individual routes or route groups that require authentication
 * without relying solely on the global `protect_all` config option:
 *
 * ```php
 * Route::get('/profile', ProfileController::class)->middleware('zitadel.auth');
 *
 * Route::middleware('zitadel.auth')->group(function () {
 *     Route::get('/dashboard', DashboardController::class);
 *     Route::get('/settings', SettingsController::class);
 * });
 * ```
 *
 * For API routes expecting JSON, unauthenticated requests receive a 401
 * JSON response. For web routes, Laravel's standard {@see AuthenticationException}
 * is thrown and redirected to the login page by the exception handler.
 */
final class ZitadelAuthenticate
{
    /**
     * Handle an incoming request.
     *
     * Checks the `zitadel` guard for an authenticated user. If the guard
     * has no user (no valid JWT cookie or Bearer token), throws
     * {@see AuthenticationException} which Laravel's exception handler
     * converts to a redirect (web) or a 401 JSON response (API).
     *
     * @param Request $request The incoming HTTP request.
     * @param Closure $next    The next middleware in the stack.
     * @return Response The response from the next handler, or an auth failure response.
     * @throws AuthenticationException When the request is unauthenticated.
     */
    public function handle(Request $request, Closure $next): Response
    {
        if (auth('zitadel')->guest()) {
            throw new AuthenticationException(
                'Unauthenticated.',
                ['zitadel'],
            );
        }

        return $next($request);
    }
}
