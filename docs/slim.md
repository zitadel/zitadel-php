# Slim 4

Slim 4 is PSR-15 native. Use the core `ZitadelMiddleware` directly — no bridge required.

## Installation

```bash
composer require zitadel/zitadel-php nyholm/psr7
```

## Setup

```php
use Nyholm\Psr7\Factory\Psr17Factory;
use Slim\Factory\AppFactory;
use Zitadel\Sdk\Auth\JwksCache;
use Zitadel\Sdk\Auth\TokenValidator;
use Zitadel\Sdk\Config\ZitadelConfig;
use Zitadel\Sdk\Middleware\ZitadelMiddleware;

$psr17    = new Psr17Factory();
$config   = new ZitadelConfig(
    issuerUrl:    $_ENV['ZITADEL_ISSUER_URL'],
    clientId:     $_ENV['ZITADEL_CLIENT_ID'],
    redirectUri:  $_ENV['ZITADEL_REDIRECT_URI'],
    cookieSecret: $_ENV['ZITADEL_COOKIE_SECRET'],
    protectAll:   true,
    ignoredRoutes: ['/health'],
);

$validator = new TokenValidator($config, new JwksCache());

$app = AppFactory::create();
$app->add(new ZitadelMiddleware($config, $validator, $psr17));
```

## Accessing Claims in Route Handlers

```php
$app->get('/dashboard', function (Request $request, Response $response): Response {
    /** @var \Zitadel\Sdk\Auth\Claims|null $claims */
    $claims = $request->getAttribute('zitadel.claims');
    $response->getBody()->write("Hello {$claims?->name}");
    return $response;
});
```

## Note on `#[AllowAnonymous]`

`#[AllowAnonymous]` is **not supported** in Slim 4. The middleware must run before
routing to intercept the callback and logout paths (no Slim routes are registered
for them). Running before routing means route information is unavailable for
reflection.

Use `ignoredRoutes` in `ZitadelConfig` to exempt specific paths:

```php
'ignoredRoutes' => ['/health', '/public/*'],
```
