# CodeIgniter 4

## Installation

```bash
composer require zitadel/zitadel-php
```

## Filter Registration

`app/Config/Filters.php`:

```php
use Zitadel\Sdk\Bridge\CodeIgniter\ZitadelFilter;

public array $aliases = [
    'zitadel' => ZitadelFilter::class,
];

public array $globals = [
    'before' => ['zitadel'],
];
```

## Environment Variables

```env
ZITADEL_ISSUER_URL=https://my.zitadel.cloud
ZITADEL_CLIENT_ID=your-client-id
ZITADEL_REDIRECT_URI=https://myapp.com/zitadel/callback
ZITADEL_COOKIE_SECRET=  # bin2hex(random_bytes(32))
```

## Accessing Claims in Controllers

CI4 has no request-attribute system. Claims are stored in the static
`ZitadelHolder` after validation:

```php
use Zitadel\Sdk\Bridge\CodeIgniter\ZitadelHolder;

class Dashboard extends BaseController
{
    public function index(): string
    {
        $claims = ZitadelHolder::claims();
        return "Hello {$claims?->name}";
    }
}
```

## Opting Out with `#[AllowAnonymous]`

```php
use Zitadel\Sdk\Attribute\AllowAnonymous;

class Health extends BaseController
{
    #[AllowAnonymous]
    public function index(): string
    {
        return 'OK';
    }
}
```

## Why `ZitadelHolder` Instead of Request Attributes

CI4's `IncomingRequest` doesn't support arbitrary attributes (unlike PSR-7
`ServerRequestInterface` or Symfony's `ParameterBag`). The static holder is the
only alternative to server-side sessions for passing claims from a filter to a
controller within the same PHP request lifecycle.

**Long-running runtimes** (Swoole, RoadRunner): reset the holder between requests
by calling `ZitadelHolder::set(null)` in your request lifecycle hook.

## Forwarding Token to Downstream Services

```php
$claims = ZitadelHolder::claims();
$client = \Config\Services::curlrequest();
$response = $client->get('https://api.internal/data', [
    'headers' => ['Authorization' => 'Bearer ' . $claims?->token],
]);
```
