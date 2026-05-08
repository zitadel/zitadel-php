# Laravel

## Installation

```bash
composer require zitadel/zitadel-php
```

The `ZitadelServiceProvider` is auto-discovered via `composer.json`'s
`extra.laravel.providers`. No manual registration needed.

## Environment Variables

```env
ZITADEL_ISSUER_URL=https://my.zitadel.cloud
ZITADEL_CLIENT_ID=your-client-id
ZITADEL_REDIRECT_URI=https://myapp.com/zitadel/callback
ZITADEL_COOKIE_SECRET=  # bin2hex(random_bytes(32))
```

## Publish Config (Optional)

```bash
php artisan vendor:publish --tag=zitadel-config
```

This copies `config/zitadel.php` to your application's config directory.

## Protecting Routes

### Option A: Protect all routes (recommended)

In `config/zitadel.php` (or via env):

```php
'protect_all' => true,
'ignored_routes' => ['/health', '/'],
```

### Option B: Protect specific routes

```php
'protect_all' => false,
'protected_routes' => ['/dashboard*', '/admin*'],
```

## Opting Out of Authentication

### Per-route (native Laravel)

```php
use Zitadel\Sdk\Bridge\Laravel\Http\Middleware\ZitadelMiddleware;

Route::get('/public', PublicController::class)
    ->withoutMiddleware(ZitadelMiddleware::class);
```

### Per-controller or per-method (library attribute)

```php
use Zitadel\Sdk\Attribute\AllowAnonymous;

#[AllowAnonymous]
class PublicController { ... }

// or on a single method:
class MyController {
    #[AllowAnonymous]
    public function landing(): Response { ... }
}
```

## Accessing Authenticated User

```php
// app/Http/Controllers/DashboardController.php
class DashboardController extends Controller
{
    public function __invoke(): string
    {
        /** @var \Zitadel\Sdk\Bridge\Laravel\Auth\ZitadelUser $user */
        $user = auth('zitadel')->user();
        return "Hello {$user->claims->name}";
    }
}
```

Or set `zitadel` as the default guard in `config/auth.php` and use `auth()->user()`.

## Auth Guard Registration

In `config/auth.php`:

```php
'guards' => [
    'zitadel' => ['driver' => 'zitadel'],
],
```

## Forwarding Token to Downstream Services

```php
$user = auth('zitadel')->user();
$response = Http::withHeaders([
    'Authorization' => 'Bearer ' . $user->claims->token,
])->get('https://api.internal/data');
```

## `auth:zitadel` Route Middleware

`->middleware('auth:zitadel')` uses Laravel's built-in `Authenticate` middleware
backed by `ZitadelGuard::check()`. Since `ZitadelMiddleware` runs first (in the
`web` group), an unauthenticated user on a `protectedRoutes`/`protectAll` path
is already redirected to Zitadel before `auth:zitadel` fires.

Use `auth:zitadel` on API routes where Bearer tokens are sent directly by the
client and the PKCE flow is managed independently.
