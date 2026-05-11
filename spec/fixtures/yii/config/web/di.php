<?php

declare(strict_types=1);

use Nyholm\Psr7\Factory\Psr17Factory;
use Psr\Http\Message\ResponseFactoryInterface;
use Yiisoft\Router\FastRoute\UrlMatcher;
use Yiisoft\Router\RouteCollection;
use Yiisoft\Router\RouteCollectionInterface;
use Yiisoft\Router\RouteCollector;
use Yiisoft\Router\UrlMatcherInterface;
use Zitadel\Sdk\Auth\JwksCache;
use Zitadel\Sdk\Auth\JwksCacheInterface;
use Zitadel\Sdk\Auth\TokenValidator;
use Zitadel\Sdk\Bridge\Yii\ZitadelMiddleware;
use Zitadel\Sdk\Config\ZitadelConfig;

$appConfig = require __DIR__ . '/application.php';

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
            'ignoredRoutes'     => ['/health'],
            'jwksPath'          => $_ENV['ZITADEL_JWKS_PATH']          ?? '/oauth/v2/keys',
            'authorizationPath' => $_ENV['ZITADEL_AUTHORIZATION_PATH'] ?? '/oauth/v2/authorize',
            'tokenPath'         => $_ENV['ZITADEL_TOKEN_PATH']         ?? '/oauth/v2/token',
            'endSessionPath'    => $_ENV['ZITADEL_END_SESSION_PATH']   ?? '/oidc/v1/end_session',
        ],
    ],

    JwksCacheInterface::class => JwksCache::class,

    JwksCache::class => JwksCache::class,

    TokenValidator::class => TokenValidator::class,

    RouteCollectionInterface::class => static function () use ($appConfig): RouteCollectionInterface {
        $collector = new RouteCollector();
        $collector->addRoute(...$appConfig['routes']);

        return new RouteCollection($collector);
    },

    UrlMatcherInterface::class => UrlMatcher::class,

    ZitadelMiddleware::class => ZitadelMiddleware::class,
];
