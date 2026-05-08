<?php

declare(strict_types=1);

return [
    /*
    |--------------------------------------------------------------------------
    | Zitadel Instance
    |--------------------------------------------------------------------------
    */
    'issuer_url'  => env('ZITADEL_ISSUER_URL', 'https://my.zitadel.cloud'),
    'client_id'   => env('ZITADEL_CLIENT_ID'),
    'redirect_uri' => env('ZITADEL_REDIRECT_URI'),

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
    'post_login_redirect'  => env('ZITADEL_POST_LOGIN_REDIRECT', '/'),
    'post_logout_redirect' => env('ZITADEL_POST_LOGOUT_REDIRECT', '/'),

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
    'scopes'               => ['openid', 'profile', 'email'],
    'clock_skew_seconds'   => 5,
    'jwks_ttl_seconds'     => 300,
    'http_timeout_seconds' => 5,
];
