<?php

declare(strict_types=1);

return [
    /*
    |--------------------------------------------------------------------------
    | Zitadel Instance
    |--------------------------------------------------------------------------
    */
    'issuer_url'  => env('ZITADEL_ISSUER_URL'),
    'client_id'   => env('ZITADEL_CLIENT_ID'),
    'redirect_uri' => rtrim((string) env('SERVER_URL', 'http://localhost:3000'), '/') . '/zitadel/callback',

    /*
    |--------------------------------------------------------------------------
    | Cookie Encryption Secret
    |--------------------------------------------------------------------------
    | Must be a 64-character hex string (32 raw bytes).
    | Generate: bin2hex(random_bytes(32))
    */
    'cookie_secret' => env('ZITADEL_COOKIE_SECRET'),

    /*
    |--------------------------------------------------------------------------
    | Paths
    |--------------------------------------------------------------------------
    */
    'callback_path'        => env('ZITADEL_CALLBACK_PATH', '/zitadel/callback'),
    'logout_path'          => env('ZITADEL_LOGOUT_PATH', '/zitadel/logout'),
    'proxy_path'           => env('ZITADEL_PROXY_PATH', '/__nextgen'),
    'post_login_redirect'  => env('ZITADEL_POST_LOGIN_URL', '/'),
    'post_logout_redirect' => env('ZITADEL_POST_LOGOUT_URL', '/'),

    /*
    |--------------------------------------------------------------------------
    | Route Protection
    |--------------------------------------------------------------------------
    */
    'protect_all'      => env('ZITADEL_PROTECT_ALL', false),
    'protected_routes' => [],
    'ignored_routes'   => [],

    /*
    |--------------------------------------------------------------------------
    | OAuth / JWT Tuning
    |--------------------------------------------------------------------------
    */
    'scopes'                  => ['openid', 'profile', 'email'],
    'clock_skew_seconds'      => 5,
    'jwks_ttl_seconds'        => 300,
    'http_timeout_seconds'    => 5,
    'pkce_cookie_ttl_seconds'    => env('ZITADEL_PKCE_COOKIE_TTL_SECONDS', 600),
    'trust_x_forwarded_proto'    => env('ZITADEL_TRUST_X_FORWARDED_PROTO', true),

    /*
    |--------------------------------------------------------------------------
    | Endpoint Path Overrides
    |--------------------------------------------------------------------------
    | Override the URL paths appended to issuer_url when building OIDC endpoint
    | URIs. The defaults match Zitadel's API paths. Override these when using a
    | non-Zitadel OIDC server (e.g. navikt/mock-oauth2-server for testing).
    */
    'jwks_path'            => env('ZITADEL_JWKS_PATH', '/oauth/v2/keys'),
    'authorization_path'   => env('ZITADEL_AUTHORIZATION_PATH', '/oauth/v2/authorize'),
    'token_path'           => env('ZITADEL_TOKEN_PATH', '/oauth/v2/token'),
    'end_session_path'     => env('ZITADEL_END_SESSION_PATH', '/oidc/v1/end_session'),
];
