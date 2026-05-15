<?php

declare(strict_types=1);

namespace Zitadel\Sdk\Bridge\CodeIgniter\Config;

use CodeIgniter\Config\BaseConfig;

/**
 * Zitadel SDK configuration for CodeIgniter 4.
 *
 * Copy this file to `app/Config/Zitadel.php` in your CI4 project and change the
 * namespace from `Zitadel\Sdk\Bridge\CodeIgniter\Config` to `Config` so that
 * CI4's `config('Zitadel')` helper can locate it by short name. Then adjust
 * `$protectAll` and `$ignoredRoutes` for your application. All credentials are
 * read from environment variables via CI4's `env()` helper, which consults the
 * `.env` file, `getenv()`, `$_ENV`, and `$_SERVER` in that order.
 *
 * Register the services in `app/Config/Services.php`:
 * ```php
 * public static function zitadelConfig(bool $getShared = true): ZitadelConfig
 * {
 *     if ($getShared) {
 *         return static::getSharedInstance('zitadelConfig');
 *     }
 *     $cfg = config('Zitadel');
 *     return new ZitadelConfig(
 *         issuerUrl:         $cfg->issuerUrl,
 *         clientId:          $cfg->clientId,
 *         redirectUri:       $cfg->redirectUri,
 *         cookieSecret:      $cfg->cookieSecret,
 *         protectAll:        $cfg->protectAll,
 *         ignoredRoutes:     $cfg->ignoredRoutes,
 *         jwksPath:          $cfg->jwksPath,
 *         authorizationPath: $cfg->authorizationPath,
 *         tokenPath:         $cfg->tokenPath,
 *         endSessionPath:    $cfg->endSessionPath,
 *     );
 * }
 * ```
 */
class Zitadel extends BaseConfig
{
    // ── Required ─────────────────────────────────────────────────────────────

    /** Base URL of your Zitadel instance (e.g. `https://my.zitadel.cloud`). */
    public string $issuerUrl = '';

    /** OAuth 2.0 client ID registered in Zitadel. */
    public string $clientId = '';

    /** Absolute redirect URI registered in Zitadel (e.g. `https://myapp.com/zitadel/callback`). */
    public string $redirectUri = '';

    /**
     * 64-character hex string used to encrypt PKCE state cookies.
     * Generate with: `bin2hex(random_bytes(32))`
     */
    public string $cookieSecret = '';

    // ── Route protection ──────────────────────────────────────────────────────

    /**
     * When `true`, every route requires authentication unless listed in
     * `$ignoredRoutes` or marked `#[AllowAnonymous]`.
     */
    public bool $protectAll = false;

    /**
     * Routes that are always publicly accessible, even when `$protectAll` is `true`.
     *
     * Entries ending with `*` are prefix wildcards (e.g. `/api/*`).
     *
     * @var string[]
     */
    public array $ignoredRoutes = [];

    /**
     * Routes that require authentication when `$protectAll` is `false`.
     *
     * @var string[]
     */
    public array $protectedRoutes = [];

    // ── SDK paths ─────────────────────────────────────────────────────────────

    /** Path the filter intercepts for the OAuth callback. */
    public string $callbackPath = '/zitadel/callback';

    /** Path the filter intercepts to initiate logout. */
    public string $logoutPath = '/zitadel/logout';

    /** Prefix for all reverse-proxied Zitadel API requests. */
    public string $proxyPath = '/__nextgen';

    /** Where to redirect after a successful login. */
    public string $postLoginRedirect = '/';

    /** Where to redirect after logout. */
    public string $postLogoutRedirect = '/';

    // ── Endpoint path overrides ───────────────────────────────────────────────

    /** Appended to `$issuerUrl` to build the JWKS endpoint. */
    public string $jwksPath = '/oauth/v2/keys';

    /** Appended to `$issuerUrl` to build the authorization endpoint. */
    public string $authorizationPath = '/oauth/v2/authorize';

    /** Appended to `$issuerUrl` to build the token endpoint. */
    public string $tokenPath = '/oauth/v2/token';

    /** Appended to `$issuerUrl` to build the end-session endpoint. */
    public string $endSessionPath = '/oidc/v1/end_session';

    // ── Tuning ────────────────────────────────────────────────────────────────

    /** OAuth 2.0 scopes requested during authorization. */
    public array $scopes = ['openid', 'profile', 'email'];

    /** Allowed clock drift in seconds when validating JWT `exp` / `nbf` claims. */
    public int $clockSkewSeconds = 5;

    /** How long (seconds) to cache the JWKS key set before re-fetching. */
    public int $jwksTtlSeconds = 300;

    /** cURL timeout in seconds for upstream HTTP calls. */
    public int $httpTimeoutSeconds = 5;

    // ─────────────────────────────────────────────────────────────────────────

    public function __construct()
    {
        $this->issuerUrl         = (string) env('ZITADEL_ISSUER_URL', '');
        $this->clientId          = (string) env('ZITADEL_CLIENT_ID', '');
        $this->redirectUri       = (string) env('ZITADEL_REDIRECT_URI', '');
        $this->cookieSecret      = (string) env('ZITADEL_COOKIE_SECRET', '');
        $this->callbackPath      = (string) env('ZITADEL_CALLBACK_PATH', '/zitadel/callback');
        $this->logoutPath        = (string) env('ZITADEL_LOGOUT_PATH', '/zitadel/logout');
        $this->proxyPath         = (string) env('ZITADEL_PROXY_PATH', '/__nextgen');
        $this->postLoginRedirect = (string) env('ZITADEL_POST_LOGIN_URL', '/');
        $this->postLogoutRedirect = (string) env('ZITADEL_POST_LOGOUT_URL', '/');
        $this->jwksPath          = (string) env('ZITADEL_JWKS_PATH', '/oauth/v2/keys');
        $this->authorizationPath = (string) env('ZITADEL_AUTHORIZATION_PATH', '/oauth/v2/authorize');
        $this->tokenPath         = (string) env('ZITADEL_TOKEN_PATH', '/oauth/v2/token');
        $this->endSessionPath    = (string) env('ZITADEL_END_SESSION_PATH', '/oidc/v1/end_session');

        parent::__construct();
    }
}
