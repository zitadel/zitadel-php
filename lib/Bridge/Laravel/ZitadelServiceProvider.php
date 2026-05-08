<?php

declare(strict_types=1);

namespace Zitadel\Sdk\Bridge\Laravel;

use Illuminate\Contracts\Http\Kernel;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\ServiceProvider;
use Zitadel\Sdk\Auth\Algorithm;
use Zitadel\Sdk\Auth\JwksCache;
use Zitadel\Sdk\Auth\TokenType;
use Zitadel\Sdk\Auth\TokenValidator;
use Zitadel\Sdk\Bridge\Laravel\Auth\ZitadelGuard;
use Zitadel\Sdk\Bridge\Laravel\Http\Middleware\ZitadelMiddleware;
use Zitadel\Sdk\Config\ZitadelConfig;

/**
 * Auto-discovered Laravel service provider for the Zitadel SDK.
 *
 * Registered automatically via the `extra.laravel.providers` key in `composer.json`.
 * No manual registration in `config/app.php` is needed.
 *
 * Registers:
 * - {@see ZitadelConfig} singleton (from env vars or published config file)
 * - {@see JwksCache} singleton (shared across all requests in the process)
 * - {@see TokenValidator} singleton
 * - Internal callback and logout routes via `loadRoutesFrom()` (route-cache compatible)
 * - {@see ZitadelMiddleware} in the `web` middleware group (after routing, before response)
 * - `zitadel` Auth guard backed by {@see ZitadelGuard}
 *
 * Publish config with:
 * ```bash
 * php artisan vendor:publish --tag=zitadel-config
 * ```
 */
final class ZitadelServiceProvider extends ServiceProvider
{
    #[\Override]
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/config/zitadel.php', 'zitadel');

        $this->app->singleton(ZitadelConfig::class, function ($app) {
            $cfg = $app['config']['zitadel'];

            return new ZitadelConfig(
                issuerUrl:          (string) ($cfg['issuer_url'] ?? ''),
                clientId:           (string) ($cfg['client_id'] ?? ''),
                redirectUri:        (string) ($cfg['redirect_uri'] ?? ''),
                cookieSecret:       (string) ($cfg['cookie_secret'] ?? ''),
                callbackPath:       (string) ($cfg['callback_path'] ?? '/zitadel/callback'),
                logoutPath:         (string) ($cfg['logout_path'] ?? '/zitadel/logout'),
                postLoginRedirect:  (string) ($cfg['post_login_redirect'] ?? '/'),
                postLogoutRedirect: (string) ($cfg['post_logout_redirect'] ?? '/'),
                protectAll:         (bool)   ($cfg['protect_all'] ?? false),
                ignoredRoutes:      (array)  ($cfg['ignored_routes'] ?? []),
                protectedRoutes:    (array)  ($cfg['protected_routes'] ?? []),
                scopes:             (array)  ($cfg['scopes'] ?? ['openid', 'profile', 'email']),
                allowedAlgorithms:  array_map(
                    static fn (string $v) => Algorithm::from($v),
                    (array) ($cfg['allowed_algorithms'] ?? [Algorithm::RS256->value, Algorithm::ES256->value])
                ),
                allowedTokenTypes:  array_map(
                    static fn (string $v) => TokenType::from($v),
                    (array) ($cfg['allowed_token_types'] ?? [TokenType::JWT->value, TokenType::AtJWT->value])
                ),
                audience:           $cfg['audience'] ?? null,
                clockSkewSeconds:   (int) ($cfg['clock_skew_seconds'] ?? 5),
                jwksTtlSeconds:     (int) ($cfg['jwks_ttl_seconds'] ?? 300),
                httpTimeoutSeconds: (int) ($cfg['http_timeout_seconds'] ?? 5),
            );
        });

        $this->app->singleton(JwksCache::class);

        $this->app->singleton(TokenValidator::class, function ($app) {
            return new TokenValidator(
                $app->make(ZitadelConfig::class),
                $app->make(JwksCache::class),
            );
        });
    }

    #[\Override]
    public function boot(Router $router): void
    {
        if ($this->app->runningInConsole()) {
            $this->publishes(
                [__DIR__ . '/config/zitadel.php' => config_path('zitadel.php')],
                'zitadel-config'
            );
        }

        $this->loadRoutesFrom(__DIR__ . '/routes/zitadel.php');

        $router->pushMiddlewareToGroup('web', ZitadelMiddleware::class);

        Auth::extend('zitadel', static function ($app) {
            return new ZitadelGuard($app['request']);
        });
    }
}
