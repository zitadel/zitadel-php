# Symfony

## Installation

```bash
composer require zitadel/zitadel-php
```

## Bundle Registration

In `config/bundles.php`:

```php
return [
    // ...
    Zitadel\Sdk\Bridge\Symfony\ZitadelBundle::class => ['all' => true],
];
```

## Configuration

`config/packages/zitadel.yaml`:

```yaml
zitadel:
    issuer_url: '%env(ZITADEL_ISSUER_URL)%'
    client_id: '%env(ZITADEL_CLIENT_ID)%'
    redirect_uri: '%env(ZITADEL_REDIRECT_URI)%'
    cookie_secret: '%env(ZITADEL_COOKIE_SECRET)%'
    protect_all: true
    ignored_routes:
        - '/health'
        - '/public/*'
```

## Environment Variables

```env
ZITADEL_ISSUER_URL=https://my.zitadel.cloud
ZITADEL_CLIENT_ID=your-client-id
ZITADEL_REDIRECT_URI=https://myapp.com/zitadel/callback
ZITADEL_COOKIE_SECRET=  # bin2hex(random_bytes(32))
```

## Accessing Claims in Controllers

The `ClaimsValueResolver` auto-resolves `?Claims $claims` in controller parameters:

```php
use Zitadel\Sdk\Auth\Claims;

class DashboardController extends AbstractController
{
    #[Route('/dashboard')]
    public function index(?Claims $claims): Response
    {
        return new Response("Hello {$claims?->name}");
    }
}
```

No service configuration needed — the resolver is auto-tagged.

### Alternative: Request Attribute

```php
$claims = $request->attributes->get('zitadel.claims'); // Claims|null
```

## Opting Out with `#[AllowAnonymous]`

```php
use Zitadel\Sdk\Attribute\AllowAnonymous;

class PublicController extends AbstractController
{
    #[Route('/landing')]
    #[AllowAnonymous]
    public function landing(): Response { ... }
}
```

## Forwarding Token to Downstream Services

```php
public function index(?Claims $claims, HttpClientInterface $httpClient): Response
{
    $response = $httpClient->request('GET', 'https://api.internal/data', [
        'headers' => ['Authorization' => 'Bearer ' . $claims?->token],
    ]);
    // ...
}
```
