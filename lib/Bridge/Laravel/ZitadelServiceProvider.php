<?php

declare(strict_types=1);

namespace Zitadel\Sdk\Bridge\Laravel;

use Illuminate\Contracts\Http\Kernel;
use Illuminate\Cookie\Middleware\EncryptCookies;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\ServiceProvider;
use Zitadel\Sdk\Auth\Algorithm;
use Zitadel\Sdk\Auth\JwksCache;
use Zitadel\Sdk\Auth\TokenType;
use Zitadel\Sdk\Auth\TokenValidator;
use Zitadel\Sdk\Bridge\Laravel\Auth\ZitadelGuard;
use Zitadel\Sdk\Bridge\Laravel\Console\ZitadelGenerateSecretCommand;
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
    /**
     * Registers all Zitadel SDK services as container singletons.
     *
     * Merges the default config, then binds {@see ZitadelConfig}, {@see JwksCache},
     * and {@see TokenValidator} into the service container.
     */
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
                proxyPath:          (string) ($cfg['proxy_path'] ?? '/__nextgen'),
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
                clockSkewSeconds:     (int) ($cfg['clock_skew_seconds'] ?? 5),
                jwksTtlSeconds:       (int) ($cfg['jwks_ttl_seconds'] ?? 300),
                httpTimeoutSeconds:   (int) ($cfg['http_timeout_seconds'] ?? 5),
                pkceCookieTtlSeconds: (int) ($cfg['pkce_cookie_ttl_seconds'] ?? 600),
                jwksPath:             (string) ($cfg['jwks_path'] ?? '/oauth/v2/keys'),
                authorizationPath:  (string) ($cfg['authorization_path'] ?? '/oauth/v2/authorize'),
                tokenPath:          (string) ($cfg['token_path'] ?? '/oauth/v2/token'),
                endSessionPath:     (string) ($cfg['end_session_path'] ?? '/oidc/v1/end_session'),
            );
        });

        $this->app->singleton(JwksCache::class);

        $this->app->singleton(TokenValidator::class, fn ($app) => new TokenValidator(
            $app->make(ZitadelConfig::class),
            $app->make(JwksCache::class),
        ));
    }

    /**
     * Bootstraps routes, middleware, config publishing, and the `zitadel` auth guard.
     *
     * @param Router $router The Illuminate router used to register the web middleware group entry.
     * @return void
     */
    public function boot(Router $router): void
    {
        if ($this->app->runningInConsole()) {
            $this->publishes(
                [__DIR__ . '/config/zitadel.php' => config_path('zitadel.php')],
                'zitadel-config'
            );

            $this->commands([ZitadelGenerateSecretCommand::class]);
        }

        // Exclude __nextgen_auth and __nextgen_pkce from Laravel's cookie encryption.
        // These cookies are already encrypted by libsodium; double-encrypting them with
        // Laravel's AES key would corrupt the values and break the authentication flow.
        // Calling the static method here means users do not need to add these names to
        // their own bootstrap/app.php encryptCookies(except: [...]) configuration.
        EncryptCookies::except(['__nextgen_auth', '__nextgen_pkce']);

        $this->loadRoutesFrom(__DIR__ . '/routes/zitadel.php');

        $router->pushMiddlewareToGroup('web', ZitadelMiddleware::class);

        // Register a short middleware alias so developers can write:
        //   Route::middleware('zitadel')->group(...)
        // This matches the pattern used by tymon/jwt-auth ('jwt.auth' etc.) and gives
        // fine-grained per-route control without referencing the full class path.
        $router->aliasMiddleware('zitadel', ZitadelMiddleware::class);

        Auth::extend('zitadel', static fn ($app) => new ZitadelGuard($app['request']));
    }
}
