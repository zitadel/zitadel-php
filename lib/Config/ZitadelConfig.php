<?php

declare(strict_types=1);

namespace Zitadel\Sdk\Config;

use Zitadel\Sdk\Auth\Algorithm;
use Zitadel\Sdk\Auth\TokenType;

/**
 * Immutable configuration for the Zitadel middleware.
 *
 * Construct once (typically in a service provider or DI container) and share
 * as a singleton. All properties are readonly; create a new instance to change
 * configuration.
 *
 * @see https://zitadel.com/docs/guides/integrate/login/oidc/oauth-recommended-flows
 */
readonly class ZitadelConfig
{
    /**
     * @param string               $issuerUrl          Base URL of the Zitadel instance.
     *                                                  Must not have a trailing slash.
     *                                                  Example: `https://my.zitadel.cloud`
     * @param string               $clientId           OAuth 2.0 client ID registered in Zitadel.
     * @param string               $redirectUri        Full URL of the callback endpoint in your app.
     *                                                  Must match the redirect URI configured in Zitadel.
     *                                                  Example: `https://myapp.com/zitadel/callback`
     * @param string               $cookieSecret       32-byte random secret used to encrypt the
     *                                                  PKCE state cookie with XChaCha20-Poly1305.
     *                                                  Must be a 64-character hex string.
     *                                                  Generate: `bin2hex(random_bytes(32))`
     * @param string               $callbackPath       URL path the middleware intercepts to handle
     *                                                  the OAuth callback and exchange the code.
     *                                                  Default: `/zitadel/callback`
     * @param string               $logoutPath         URL path the middleware intercepts to clear
     *                                                  the session cookie and redirect to Zitadel's
     *                                                  end-session endpoint.
     *                                                  Default: `/zitadel/logout`
     * @param string               $proxyPath          URL path prefix the middleware intercepts to
     *                                                  reverse-proxy requests to `$issuerUrl`.
     *                                                  Strips the prefix and forwards the remainder
     *                                                  (e.g. `/__nextgen/oauth/v2/keys` →
     *                                                  `$issuerUrl/oauth/v2/keys`).
     *                                                  Default: `/__nextgen`
     * @param string               $postLoginRedirect  Where to redirect after a successful login.
     *                                                  The PKCE state cookie overrides this with the
     *                                                  originally requested path when one is available.
     *                                                  Default: `/`
     * @param string               $postLogoutRedirect Where to redirect after logout.
     *                                                  Sent as `post_logout_redirect_uri` to Zitadel.
     *                                                  Default: `/`
     * @param bool                 $protectAll         When `true`, ALL routes require a valid session
     *                                                  unless the path is in `$ignoredRoutes` or the
     *                                                  matched controller carries `#[AllowAnonymous]`
     *                                                  (where supported).
     *                                                  When `false` (default), only paths in
     *                                                  `$protectedRoutes` require auth.
     * @param string[]             $ignoredRoutes      Paths skipped entirely — no token validation,
     *                                                  no PKCE redirect. Supports `prefix*` wildcards.
     *                                                  Example: `['/health', '/public/*']`
     * @param string[]             $protectedRoutes    Paths that require a valid session. Unauthenticated
     *                                                  requests are redirected to Zitadel for login.
     *                                                  Supports `prefix*` wildcard patterns.
     *                                                  Example: `['/admin*', '/dashboard*']`
     * @param string[]             $scopes             OAuth 2.0 scopes requested during authorization.
     *                                                  Must include `openid` for OIDC claims.
     *                                                  Default: `['openid', 'profile', 'email']`
     * @param Algorithm[]          $allowedAlgorithms  JWT signing algorithms accepted during token
     *                                                  validation.
     *                                                  Default: `[Algorithm::RS256, Algorithm::ES256]`
     * @param TokenType[]          $allowedTokenTypes  Accepted `typ` header values.
     *                                                  Default: `[TokenType::JWT, TokenType::AtJWT]`
     * @param string|string[]|null $audience           Expected `aud` claim value. When set, the token
     *                                                  must contain this audience. Accepts a single
     *                                                  string or an array when multiple are valid.
     *                                                  Default: `null` (audience check skipped)
     * @param int                  $clockSkewSeconds   Tolerance applied to `exp`, `nbf`, and `iat`
     *                                                  checks to account for clock drift.
     *                                                  Default: `5`
     * @param int                  $jwksTtlSeconds     How long (seconds) a fetched JWKS key set is
     *                                                  cached in-process before re-fetching.
     *                                                  Default: `300`
     * @param int                  $httpTimeoutSeconds Timeout (seconds) for HTTP calls: JWKS key
     *                                                  fetch and authorization code exchange.
     *                                                  Default: `5`
     * @param string               $jwksPath           URL path for the JWKS endpoint, relative to
     *                                                  `$issuerUrl`. Override for non-Zitadel servers
     *                                                  (e.g. `/jwks` for navikt mock-oauth2-server).
     *                                                  Default: `/oauth/v2/keys`
     * @param string               $authorizationPath  URL path for the authorization endpoint.
     *                                                  Default: `/oauth/v2/authorize`
     * @param string               $tokenPath          URL path for the token endpoint.
     *                                                  Default: `/oauth/v2/token`
     * @param string               $endSessionPath     URL path for the end-session endpoint.
     *                                                  Default: `/oidc/v1/end_session`
     * @throws \InvalidArgumentException If `$redirectUri` is not an absolute URL with a non-empty
     *                                   host, `$cookieSecret` is not a 64-character hex string,
     *                                   `$clockSkewSeconds` or `$jwksTtlSeconds` or
     *                                   `$httpTimeoutSeconds` are negative, or
     *                                   `$allowedAlgorithms` / `$allowedTokenTypes` are empty.
     */
    public function __construct(
        // ── Required: OIDC identity ──────────────────────────────────────────
        public string               $issuerUrl,
        public string               $clientId,
        public string               $redirectUri,
        // ── Required: security credential ───────────────────────────────────
        #[\SensitiveParameter]
        public string               $cookieSecret,
        // ── Optional: routing / paths ────────────────────────────────────────
        public string               $callbackPath       = '/zitadel/callback',
        public string               $logoutPath         = '/zitadel/logout',
        public string               $proxyPath          = '/__nextgen',
        public string               $postLoginRedirect  = '/',
        public string               $postLogoutRedirect = '/',
        // ── Optional: route protection policy ───────────────────────────────
        public bool                 $protectAll         = false,
        public array                $ignoredRoutes      = [],
        public array                $protectedRoutes    = [],
        // ── Optional: OAuth / JWT tuning ─────────────────────────────────────
        public array                $scopes             = ['openid', 'profile', 'email'],
        public array                $allowedAlgorithms  = [Algorithm::RS256, Algorithm::ES256],
        public array                $allowedTokenTypes  = [TokenType::JWT, TokenType::AtJWT],
        public string|array|null    $audience           = null,
        public int                  $clockSkewSeconds   = 5,
        public int                  $jwksTtlSeconds     = 300,
        public int                  $httpTimeoutSeconds = 5,
        // ── Optional: endpoint path overrides (for non-Zitadel OIDC servers) ─
        public string               $jwksPath           = '/oauth/v2/keys',
        public string               $authorizationPath  = '/oauth/v2/authorize',
        public string               $tokenPath          = '/oauth/v2/token',
        public string               $endSessionPath     = '/oidc/v1/end_session',
    ) {
        foreach (['protectedRoutes' => $protectedRoutes, 'ignoredRoutes' => $ignoredRoutes] as $name => $value) {
            if (!array_is_list($value)) {
                throw new \InvalidArgumentException(
                    "[zitadel] {$name} must be a sequential array, not an associative map."
                );
            }
        }

        $keyBytes = hex2bin($cookieSecret);
        if ($keyBytes === false || strlen($keyBytes) !== SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES) {
            throw new \InvalidArgumentException(
                '[zitadel] cookieSecret must be a 64-character hex string (32 raw bytes). ' .
                'Generate with: bin2hex(random_bytes(32))'
            );
        }

        if (
            !str_starts_with($issuerUrl, 'https://') &&
            !str_starts_with($issuerUrl, 'http://localhost') &&
            !str_starts_with($issuerUrl, 'http://127.')
        ) {
            throw new \InvalidArgumentException(
                '[zitadel] issuerUrl must use https://. HTTP is only permitted for localhost development. ' .
                "Received: \"{$issuerUrl}\""
            );
        }

        if (str_ends_with($issuerUrl, '/')) {
            throw new \InvalidArgumentException(
                '[zitadel] issuerUrl must not have a trailing slash. ' .
                "Received: \"{$issuerUrl}\". The iss claim in JWTs is compared by strict " .
                'equality, so a trailing slash causes every token to be rejected silently.'
            );
        }

        if (str_ends_with(rtrim($issuerUrl, '/'), '/.well-known/openid-configuration')) {
            throw new \InvalidArgumentException(
                '[zitadel] issuerUrl must be the base URL (e.g. https://my.zitadel.cloud), ' .
                'not the discovery URL. Remove the /.well-known/openid-configuration suffix.'
            );
        }

        $parsedRedirectUri = parse_url($redirectUri);
        $redirectUriHost   = $parsedRedirectUri['host'] ?? '';
        if (
            $redirectUriHost === '' ||
            (
                !str_starts_with($redirectUri, 'https://') &&
                !str_starts_with($redirectUri, 'http://localhost') &&
                !str_starts_with($redirectUri, 'http://127.')
            )
        ) {
            throw new \InvalidArgumentException(
                '[zitadel] redirectUri must be an absolute URL with a non-empty host. ' .
                'HTTP is only permitted for localhost development. ' .
                "Received: \"{$redirectUri}\""
            );
        }

        foreach (['callbackPath' => $callbackPath, 'logoutPath' => $logoutPath, 'proxyPath' => $proxyPath] as $name => $value) {
            if (!str_starts_with($value, '/') || str_starts_with($value, '//')) {
                throw new \InvalidArgumentException(
                    "[zitadel] {$name} must be a relative path starting with a single \"/\". " .
                    "Received: \"{$value}\"."
                );
            }
        }

        foreach (['postLoginRedirect' => $postLoginRedirect, 'postLogoutRedirect' => $postLogoutRedirect] as $name => $value) {
            if (!str_starts_with($value, '/') || str_starts_with($value, '//')) {
                throw new \InvalidArgumentException(
                    "[zitadel] {$name} must be a relative path starting with a single \"/\". " .
                    "Received: \"{$value}\". Using an absolute or protocol-relative URL " .
                    'would allow open-redirect attacks.'
                );
            }
        }

        if ($clockSkewSeconds < 0 || $jwksTtlSeconds < 0 || $httpTimeoutSeconds < 0) {
            throw new \InvalidArgumentException(
                '[zitadel] clockSkewSeconds, jwksTtlSeconds, and httpTimeoutSeconds must be non-negative integers.'
            );
        }

        if ($allowedAlgorithms === [] || $allowedTokenTypes === []) {
            throw new \InvalidArgumentException(
                '[zitadel] allowedAlgorithms and allowedTokenTypes must not be empty arrays.'
            );
        }
    }

    /** Returns the JWKS endpoint URI. */
    public function jwksUri(): string
    {
        return rtrim($this->issuerUrl, '/') . $this->jwksPath;
    }

    /** Returns the OAuth 2.0 authorization endpoint URI. */
    public function authorizationEndpoint(): string
    {
        return rtrim($this->issuerUrl, '/') . $this->authorizationPath;
    }

    /** Returns the OAuth 2.0 token endpoint URI. */
    public function tokenEndpoint(): string
    {
        return rtrim($this->issuerUrl, '/') . $this->tokenPath;
    }

    /** Returns the OIDC end-session endpoint URI for single sign-out. */
    public function endSessionEndpoint(): string
    {
        return rtrim($this->issuerUrl, '/') . $this->endSessionPath;
    }

    /**
     * Builds the absolute post-logout redirect URI.
     *
     * The `postLogoutRedirect` config value is a relative path (e.g. `/` or
     * `/goodbye`). ZITADEL and other OIDC providers require an absolute URI in
     * the `post_logout_redirect_uri` parameter, and perform exact-match checks
     * against the registered URIs.
     *
     * The base origin is inferred from `redirectUri` (which is already absolute)
     * so no framework-specific request object is needed.
     *
     * Examples:
     *  - redirectUri=http://localhost:3000/zitadel/callback, postLogoutRedirect=/
     *    → http://localhost:3000
     *  - redirectUri=https://myapp.com/zitadel/callback, postLogoutRedirect=/bye
     *    → https://myapp.com/bye
     */
    public function postLogoutAbsoluteUri(): string
    {
        $parsed = parse_url($this->redirectUri);
        $origin = ($parsed['scheme'] ?? 'https') . '://' . ($parsed['host'] ?? '');
        if (isset($parsed['port'])) {
            $origin .= ':' . $parsed['port'];
        }

        $path = $this->postLogoutRedirect;

        return $origin . ($path === '/' ? '' : $path);
    }
}
