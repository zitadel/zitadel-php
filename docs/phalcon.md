# Phalcon

## Installation

```bash
composer require zitadel/zitadel-php
```

## Micro Application

```php
use Phalcon\Mvc\Micro;
use Zitadel\Sdk\Auth\JwksCache;
use Zitadel\Sdk\Auth\TokenValidator;
use Zitadel\Sdk\Bridge\Phalcon\ZitadelMicroPlugin;
use Zitadel\Sdk\Config\ZitadelConfig;

$config = new ZitadelConfig(
    issuerUrl:    $_ENV['ZITADEL_ISSUER_URL'],
    clientId:     $_ENV['ZITADEL_CLIENT_ID'],
    redirectUri:  $_ENV['ZITADEL_REDIRECT_URI'],
    cookieSecret: $_ENV['ZITADEL_COOKIE_SECRET'],
    protectAll:   true,
    ignoredRoutes: ['/health'],
);

$validator = new TokenValidator($config, new JwksCache());
$app       = new Micro();
$app->before(new ZitadalMicroPlugin($config, $validator));

$app->get('/dashboard', function () use ($app) {
    $claims = $app->getDI()->get('zitadel.claims');
    echo "Hello {$claims?->name}";
});

$app->handle($_SERVER['REQUEST_URI']);
```

**Note**: `#[AllowAnonymous]` is not supported for Micro — Phalcon Micro routes
are closures and cannot carry PHP attributes. Use `ignoredRoutes` instead.

## MVC Application

`app/config/services.php`:

```php
use Phalcon\Events\Manager as EventsManager;
use Zitadel\Sdk\Auth\JwksCache;
use Zitadel\Sdk\Auth\TokenValidator;
use Zitadel\Sdk\Bridge\Phalcon\ZitadelPlugin;
use Zitadel\Sdk\Config\ZitadelConfig;

$config = new ZitadelConfig(
    issuerUrl:    $_ENV['ZITADEL_ISSUER_URL'],
    clientId:     $_ENV['ZITADEL_CLIENT_ID'],
    redirectUri:  $_ENV['ZITADEL_REDIRECT_URI'],
    cookieSecret: $_ENV['ZITADEL_COOKIE_SECRET'],
    protectAll:   true,
    ignoredRoutes: ['/health'],
);

$validator = new TokenValidator($config, new JwksCache());
$plugin    = new ZitadelPlugin($config, $validator);

$eventsManager = new EventsManager();
$eventsManager->attach('application', $plugin);
$eventsManager->attach('dispatch', $plugin);

$app->setEventsManager($eventsManager);
$app->getDI()->get('dispatcher')->setEventsManager($eventsManager);
```

`public/index.php` — handle the `false` return from `handle()`:

```php
$result = $app->handle($_SERVER['REQUEST_URI']);
if ($result !== false) {
    echo $result->getContent();
}
```

`ZitadelPlugin` calls `$response->send()` and returns `false` when it short-circuits
(callback, logout, or protected-route redirect). The `if ($result !== false)` guard
prevents double-output.

## Accessing Claims in MVC Controllers

```php
class DashboardController extends Controller
{
    public function indexAction(): string
    {
        /** @var \Zitadel\Sdk\Auth\Claims|null $claims */
        $claims = $this->di->get('zitadel.claims');
        return "Hello {$claims?->name}";
    }
}
```

## Opting Out with `#[AllowAnonymous]` (MVC Only)

```php
use Zitadel\Sdk\Attribute\AllowAnonymous;

class PublicController extends Controller
{
    #[AllowAnonymous]
    public function healthAction(): string
    {
        return 'OK';
    }
}
```

The `dispatch:beforeDispatch` event fires after the controller+action is resolved.
`ZitadelPlugin` checks `#[AllowAnonymous]` at that point.
