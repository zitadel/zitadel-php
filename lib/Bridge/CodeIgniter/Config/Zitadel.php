<?php

declare(strict_types=1);

namespace Zitadel\Sdk\Bridge\CodeIgniter\Config;

use CodeIgniter\Config\BaseConfig;
use Zitadel\Sdk\Auth\Algorithm;
use Zitadel\Sdk\Auth\TokenType;

/**
 * Zitadel SDK configuration for CodeIgniter 4.
 *
 * Run `php spark zitadel:publish` to copy a minimal stub to `app/Config/Zitadel.php`.
 * The generated file is intentionally empty — all settings are read from environment
 * variables, so you only need to create the file if you want to override a property in
 * code rather than via `.env`.
 *
 * Required environment variables:
 * - `ZITADEL_ISSUER_URL`   — base URL of your Zitadel instance (no trailing slash)
 * - `ZITADEL_CLIENT_ID`    — OAuth 2.0 client ID registered in Zitadel
 * - `ZITADEL_COOKIE_SECRET`— 64-character hex string (`bin2hex(random_bytes(32))`)
 * - `SERVER_URL`           — base URL of your app (used to derive the redirect URI
 *                            when `ZITADEL_REDIRECT_URI` is not set explicitly)
 *
 * Optional environment variables (all have sensible defaults):
 * - `ZITADEL_PROTECT_ALL`  — set to `true` to require auth on every route
 * - `ZITADEL_REDIRECT_URI` — explicit redirect URI (overrides the `SERVER_URL` derivation)
 * - `ZITADEL_POST_LOGIN_URL` / `ZITADEL_POST_LOGOUT_URL` — redirect paths after auth
 * - `ZITADEL_CALLBACK_PATH` / `ZITADEL_LOGOUT_PATH` / `ZITADEL_PROXY_PATH`
 *
 * No changes to `Services.php` or `Filters.php` are required:
 *
 * - **Filter auto-registration** — {@see \Zitadel\Sdk\Config\Registrar} hooks into
 *   CI4's Composer module discovery and registers `ZitadelFilter` as a global
 *   `before` filter automatically.
 *
 * - **Self-configuration** — `ZitadelFilter` calls `config('Zitadel')` internally
 *   when instantiated without arguments, resolving your subclass first.
 *
 * All credentials are read from environment variables via CI4's `env()` helper,
 * which consults `.env`, `getenv()`, `$_ENV`, and `$_SERVER` in that order.
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

    /**
     * OAuth 2.0 scopes requested during authorization.
     *
     * @var string[]
     */
    public array $scopes = ['openid', 'profile', 'email'];

    /**
     * JWT signing algorithms accepted during token validation.
     * Override to restrict to a specific algorithm (e.g. `[Algorithm::RS256]`).
     *
     * @var Algorithm[]
     */
    public array $allowedAlgorithms = [Algorithm::RS256, Algorithm::ES256];

    /**
     * Accepted `typ` header values in the JWT.
     *
     * @var TokenType[]
     */
    public array $allowedTokenTypes = [TokenType::JWT, TokenType::AtJWT];

    /**
     * Expected `aud` claim value. When set, the token must contain this audience.
     * Default: `null` (audience check skipped — not recommended for production).
     *
     * @var string|string[]|null
     */
    public string|array|null $audience = null;

    /** Allowed clock drift in seconds when validating JWT `exp` / `nbf` claims. */
    public int $clockSkewSeconds = 5;

    /** How long (seconds) to cache the JWKS key set before re-fetching. */
    public int $jwksTtlSeconds = 300;

    /** cURL timeout in seconds for upstream HTTP calls. */
    public int $httpTimeoutSeconds = 5;

    /** Lifetime (seconds) of the __nextgen_pkce PKCE state cookie set during login redirect. */
    public int $pkceCookieTtlSeconds = 600;

    /**
     * Whether to trust the X-Forwarded-Proto header for deciding the Secure cookie flag.
     * Set to false when the application is not behind a trusted reverse proxy.
     */
    public bool $trustXForwardedProto = true;

    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Populates all properties from environment variables via CI4's `env()` helper.
     *
     * Each setting falls back to a sensible default when the environment variable is
     * absent. Only `ZITADEL_ISSUER_URL`, `ZITADEL_CLIENT_ID`, `ZITADEL_COOKIE_SECRET`,
     * and either `ZITADEL_REDIRECT_URI` or `SERVER_URL` are strictly required at runtime.
     *
     * When `ZITADEL_REDIRECT_URI` is not set, the redirect URI is derived automatically
     * from `SERVER_URL` and the configured callback path, e.g.:
     * `SERVER_URL=https://myapp.com` → `redirectUri=https://myapp.com/zitadel/callback`
     */
    public function __construct()
    {
        $this->issuerUrl          = (string) env('ZITADEL_ISSUER_URL', '');
        $this->clientId           = (string) env('ZITADEL_CLIENT_ID', '');
        $this->cookieSecret       = (string) env('ZITADEL_COOKIE_SECRET', '');
        $this->callbackPath       = (string) env('ZITADEL_CALLBACK_PATH', '/zitadel/callback');
        $this->logoutPath         = (string) env('ZITADEL_LOGOUT_PATH', '/zitadel/logout');
        $this->proxyPath          = (string) env('ZITADEL_PROXY_PATH', '/__nextgen');
        $this->postLoginRedirect  = (string) env('ZITADEL_POST_LOGIN_URL', '/');
        $this->postLogoutRedirect = (string) env('ZITADEL_POST_LOGOUT_URL', '/');
        $this->jwksPath           = (string) env('ZITADEL_JWKS_PATH', '/oauth/v2/keys');
        $this->authorizationPath  = (string) env('ZITADEL_AUTHORIZATION_PATH', '/oauth/v2/authorize');
        $this->tokenPath          = (string) env('ZITADEL_TOKEN_PATH', '/oauth/v2/token');
        $this->endSessionPath     = (string) env('ZITADEL_END_SESSION_PATH', '/oidc/v1/end_session');
        $this->protectAll         = (bool) env('ZITADEL_PROTECT_ALL', false);

        // Audience defaults to null (falls back to clientId in ZitadelConfig).
        // Set ZITADEL_AUDIENCE explicitly to match a non-standard audience claim.
        $envAudience    = env('ZITADEL_AUDIENCE');
        $this->audience = is_string($envAudience) && $envAudience !== '' ? $envAudience : null;

        $envPkceTtl = env('ZITADEL_PKCE_COOKIE_TTL_SECONDS');
        if ($envPkceTtl !== null) {
            $this->pkceCookieTtlSeconds = (int) $envPkceTtl;
        }

        $envTrustXfp = env('ZITADEL_TRUST_X_FORWARDED_PROTO');
        if ($envTrustXfp !== null) {
            $this->trustXForwardedProto = filter_var($envTrustXfp, FILTER_VALIDATE_BOOLEAN);
        }

        // Derive redirectUri from SERVER_URL when ZITADEL_REDIRECT_URI is absent.
        // This keeps the common case (deploy to a known domain) zero-configuration.
        $explicitRedirectUri = (string) env('ZITADEL_REDIRECT_URI', '');
        if ($explicitRedirectUri !== '') {
            $this->redirectUri = $explicitRedirectUri;
        } else {
            $serverUrl         = rtrim((string) env('SERVER_URL', 'http://localhost:3000'), '/');
            $this->redirectUri = $serverUrl . $this->callbackPath;
        }

        parent::__construct();
    }
}
