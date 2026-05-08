# Mezzio (Laminas)

Mezzio is PSR-15 native. Use the core `ZitadelMiddleware` directly — no bridge required.

## Installation

```bash
composer require zitadel/zitadel-php nyholm/psr7
```

## Setup

Add `ZitadelMiddleware` to the pipeline **before** `RouteMiddleware` (if you
want callback/logout to work without routes) or **after** `RouteMiddleware` (if
you need `#[AllowAnonymous]` support):

### Before routing (callback + logout work, no `#[AllowAnonymous]`)

`config/pipeline.php`:

```php
use Zitadel\Sdk\Middleware\ZitadelMiddleware;

$app->pipe(ZitadelMiddleware::class);
$app->pipe(RouteMiddleware::class);
$app->pipe(DispatchMiddleware::class);
```

### After routing (`#[AllowAnonymous]` works, callback/logout need routes)

```php
$app->pipe(RouteMiddleware::class);
$app->pipe(ZitadelMiddleware::class);
$app->pipe(DispatchMiddleware::class);
```

## DI Container Binding

`config/autoload/zitadel.global.php`:

```php
use Nyholm\Psr7\Factory\Psr17Factory;
use Psr\Http\Message\ResponseFactoryInterface;
use Zitadel\Sdk\Auth\JwksCache;
use Zitadel\Sdk\Auth\TokenValidator;
use Zitadel\Sdk\Config\ZitadelConfig;
use Zitadel\Sdk\Middleware\ZitadelMiddleware;

return [
    'dependencies' => [
        'factories' => [
            ZitadelConfig::class => fn() => new ZitadelConfig(
                issuerUrl:    $_ENV['ZITADEL_ISSUER_URL'],
                clientId:     $_ENV['ZITADEL_CLIENT_ID'],
                redirectUri:  $_ENV['ZITADEL_REDIRECT_URI'],
                cookieSecret: $_ENV['ZITADEL_COOKIE_SECRET'],
                protectAll:   true,
            ),
        ],
        'invokables' => [
            JwksCache::class             => JwksCache::class,
            ResponseFactoryInterface::class => Psr17Factory::class,
        ],
    ],
];
```

## Accessing Claims in Request Handlers

```php
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Zitadel\Sdk\Auth\Claims;

class DashboardHandler implements RequestHandlerInterface
{
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        /** @var Claims|null $claims */
        $claims = $request->getAttribute('zitadel.claims');
        // ...
    }
}
```
