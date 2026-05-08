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

        if (str_ends_with(rtrim($issuerUrl, '/'), '/.well-known/openid-configuration')) {
            throw new \InvalidArgumentException(
                '[zitadel] issuerUrl must be the base URL (e.g. https://my.zitadel.cloud), ' .
                'not the discovery URL. Remove the /.well-known/openid-configuration suffix.'
            );
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
    }

    /** Returns the JWKS endpoint URI derived from the issuer URL. */
    public function jwksUri(): string
    {
        return rtrim($this->issuerUrl, '/') . '/oauth/v2/keys';
    }

    /** Returns the OAuth 2.0 authorization endpoint URI. */
    public function authorizationEndpoint(): string
    {
        return rtrim($this->issuerUrl, '/') . '/oauth/v2/authorize';
    }

    /** Returns the OAuth 2.0 token endpoint URI. */
    public function tokenEndpoint(): string
    {
        return rtrim($this->issuerUrl, '/') . '/oauth/v2/token';
    }

    /** Returns the OIDC end-session endpoint URI for single sign-out. */
    public function endSessionEndpoint(): string
    {
        return rtrim($this->issuerUrl, '/') . '/oidc/v1/end_session';
    }
}
