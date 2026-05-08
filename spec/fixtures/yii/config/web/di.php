<?php

declare(strict_types=1);

use Nyholm\Psr7\Factory\Psr17Factory;
use Psr\Http\Message\ResponseFactoryInterface;
use Zitadel\Sdk\Auth\Algorithm;
use Zitadel\Sdk\Auth\JwksCache;
use Zitadel\Sdk\Auth\TokenValidator;
use Zitadel\Sdk\Config\ZitadelConfig;
use Zitadel\Sdk\Middleware\ZitadelMiddleware;

return [
    ResponseFactoryInterface::class => Psr17Factory::class,

    ZitadelConfig::class => [
        '__class' => ZitadelConfig::class,
        '__construct()' => [
            'issuerUrl'    => $_ENV['ZITADEL_ISSUER_URL'],
            'clientId'     => $_ENV['ZITADEL_CLIENT_ID'],
            'redirectUri'  => $_ENV['ZITADEL_REDIRECT_URI'],
            'cookieSecret' => $_ENV['ZITADEL_COOKIE_SECRET'],
            'protectAll'   => true,
            'ignoredRoutes' => ['/health'],
        ],
    ],

    JwksCache::class => ['__class' => JwksCache::class],

    TokenValidator::class => ['__class' => TokenValidator::class],

    ZitadelMiddleware::class => ['__class' => ZitadelMiddleware::class],
];
