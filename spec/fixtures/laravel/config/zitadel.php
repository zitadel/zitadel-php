<?php

declare(strict_types=1);

return [
    'issuer_url'         => env('ZITADEL_ISSUER_URL', 'https://my.zitadel.cloud'),
    'client_id'          => env('ZITADEL_CLIENT_ID'),
    'redirect_uri'       => env('ZITADEL_REDIRECT_URI'),
    'cookie_secret'      => env('ZITADEL_COOKIE_SECRET'),
    'callback_path'      => env('ZITADEL_CALLBACK_PATH', '/zitadel/callback'),
    'logout_path'        => env('ZITADEL_LOGOUT_PATH', '/zitadel/logout'),
    'post_login_redirect'  => env('ZITADEL_POST_LOGIN_REDIRECT', '/'),
    'post_logout_redirect' => env('ZITADEL_POST_LOGOUT_REDIRECT', '/'),
    'protect_all'        => env('ZITADEL_PROTECT_ALL', true),
    'protected_routes'   => [],
    'ignored_routes'     => ['/health'],
    'scopes'             => ['openid', 'profile', 'email'],
    'clock_skew_seconds' => 5,
    'jwks_ttl_seconds'   => 300,
    'http_timeout_seconds' => 5,
    'jwks_path'          => env('ZITADEL_JWKS_PATH', '/oauth/v2/keys'),
    'authorization_path' => env('ZITADEL_AUTHORIZATION_PATH', '/oauth/v2/authorize'),
    'token_path'         => env('ZITADEL_TOKEN_PATH', '/oauth/v2/token'),
    'end_session_path'   => env('ZITADEL_END_SESSION_PATH', '/oidc/v1/end_session'),
];
