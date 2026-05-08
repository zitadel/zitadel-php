# Yii 3

## Installation

```bash
composer require zitadel/zitadel-php nyholm/psr7
```

## DI Container Configuration

`config/web/di.php`:

```php
use Nyholm\Psr7\Factory\Psr17Factory;
use Psr\Http\Message\ResponseFactoryInterface;
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

    JwksCache::class    => ['__class' => JwksCache::class],
    TokenValidator::class => ['__class' => TokenValidator::class],
    ZitadelMiddleware::class => ['__class' => ZitadelMiddleware::class],
];
```

## Middleware Pipeline

Add `ZitadelMiddleware` **before** `Router::class` in your application config:

```php
// config/web/application.php
use Yiisoft\Router\Middleware\Router;
use Zitadel\Sdk\Middleware\ZitadelMiddleware;

return [
    'middlewares' => [
        ZitadelMiddleware::class,
        Router::class,
    ],
];
```

## Accessing Claims in Action Handlers

```php
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Zitadel\Sdk\Auth\Claims;

class DashboardAction
{
    public function __invoke(
        ServerRequestInterface $request,
        ResponseInterface      $response,
    ): ResponseInterface {
        /** @var Claims|null $claims */
        $claims = $request->getAttribute('zitadel.claims');
        $response->getBody()->write("Hello {$claims?->name}");
        return $response;
    }
}
```

## Opting Out with `#[AllowAnonymous]`

Add `ZitadelMiddleware` **after** `Router::class` to enable `#[AllowAnonymous]`
reflection (routing must resolve first). Note: in this configuration, place the
middleware after the router in the pipeline:

```php
'middlewares' => [
    Router::class,
    ZitadelMiddleware::class,
    // ... other middleware
],
```
