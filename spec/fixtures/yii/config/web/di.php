<?php

declare(strict_types=1);

use Nyholm\Psr7\Factory\Psr17Factory;
use Psr\Http\Message\ResponseFactoryInterface;
use Zitadel\Sdk\Auth\JwksCache;
use Zitadel\Sdk\Auth\JwksCacheInterface;
use Zitadel\Sdk\Auth\TokenValidator;
use Zitadel\Sdk\Config\ZitadelConfig;
use Zitadel\Sdk\Middleware\ZitadelMiddleware;

return [
    ResponseFactoryInterface::class => Psr17Factory::class,

    ZitadelConfig::class => [
        'class' => ZitadelConfig::class,
        '__construct()' => [
            'issuerUrl'         => $_ENV['ZITADEL_ISSUER_URL']         ?? '',
            'clientId'          => $_ENV['ZITADEL_CLIENT_ID']          ?? '',
            'redirectUri'       => $_ENV['ZITADEL_REDIRECT_URI']       ?? '',
            'cookieSecret'      => $_ENV['ZITADEL_COOKIE_SECRET']      ?? '',
            'protectAll'        => true,
            'ignoredRoutes'     => ['/health', '/home'],
            'jwksPath'          => $_ENV['ZITADEL_JWKS_PATH']          ?? '/oauth/v2/keys',
            'authorizationPath' => $_ENV['ZITADEL_AUTHORIZATION_PATH'] ?? '/oauth/v2/authorize',
            'tokenPath'         => $_ENV['ZITADEL_TOKEN_PATH']         ?? '/oauth/v2/token',
            'endSessionPath'    => $_ENV['ZITADEL_END_SESSION_PATH']   ?? '/oidc/v1/end_session',
        ],
    ],

    JwksCacheInterface::class => JwksCache::class,

    JwksCache::class => JwksCache::class,

    TokenValidator::class => TokenValidator::class,

    ZitadelMiddleware::class => ZitadelMiddleware::class,
];
