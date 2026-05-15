# Zitadel PHP SDK

Official PHP middleware library for Zitadel authentication using the OAuth 2.0
Authorization Code + PKCE flow.

- Zero server-side sessions — all state in encrypted HttpOnly cookies
- Zero custom routes — middleware intercepts callback and logout automatically
- Zero external runtime dependencies — only `ext-openssl`, `ext-sodium`, `ext-curl`
- PHP 8.3+ with full `readonly class` immutability
- Supports Laravel, Symfony, Yii 3, CodeIgniter 4, and Phalcon

## Installation

```bash
composer require zitadel/sdk
```

## Quick Start

### Laravel

Auto-discovered. Set environment variables and optionally publish config:

```bash
php artisan vendor:publish --tag=zitadel-config
```

### Symfony

```php
// config/bundles.php
Zitadel\Sdk\Bridge\Symfony\ZitadelBundle::class => ['all' => true],
```

### Yii 3

Register the bridge middleware and its router bindings in `config/web/di.php`:

```php
use Zitadel\Sdk\Bridge\Yii\ZitadelMiddleware;
use Yiisoft\Router\FastRoute\UrlMatcher;
use Yiisoft\Router\UrlMatcherInterface;
// ... see docs/yii.rst for the full DI config
```

Place `ZitadelMiddleware::class` before `Router::class` in your middleware pipeline.

### Slim 4 / Mezzio (PSR-15 native)

```php
$app->add(new ZitadelMiddleware($config, $validator, $responseFactory));
```

## Configuration

```php
$config = new ZitadelConfig(
    issuerUrl:    'https://my.zitadel.cloud',
    clientId:     'your-client-id',
    redirectUri:  'https://myapp.com/zitadel/callback',
    cookieSecret: bin2hex(random_bytes(32)),  // generate once, store in env
    protectAll:   true,
    ignoredRoutes: ['/health', '/'],
);
```

## Documentation

See [docs/index.rst](docs/index.rst) or the per-framework guides in `docs/`.

## License

Apache 2.0 — see [LICENSE](LICENSE).
