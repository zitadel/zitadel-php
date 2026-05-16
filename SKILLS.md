# Integrating zitadel/sdk

This SDK implements OAuth 2.0 PKCE authentication for PHP web applications.
It handles the full login/logout lifecycle, validates JWTs issued by Zitadel,
and protects routes — all without storing any server-side session state.
Everything lives in two short-lived encrypted cookies.

---

## How it works

1. An unauthenticated request hits a protected route.
2. The middleware generates a PKCE verifier/challenge, stores them in an
   encrypted `__nextgen_pkce` cookie, and redirects the browser to Zitadel.
3. After login, Zitadel redirects back to `/zitadel/callback?code=...`.
4. The middleware exchanges the code for tokens, validates the JWT
   (signature + claims), stores it in `__nextgen_auth`, and redirects to
   the original destination.
5. On subsequent requests the middleware reads the cookie, re-validates
   the JWT, and makes `Claims` available to controllers.

---

## Environment variables

All five examples use the same `.env` keys:

```dotenv
SERVER_URL="http://localhost:3000"          # base URL of your app (no trailing slash)
ZITADEL_ISSUER_URL="https://…zitadel.cloud" # your Zitadel instance URL
ZITADEL_CLIENT_ID="…"                       # application client ID
ZITADEL_COOKIE_SECRET="…"                   # 64-char hex — see generate-secret commands below
ZITADEL_POST_LOGIN_URL="/profile"           # where to send the user after login
ZITADEL_POST_LOGOUT_URL="/"                 # where to send the user after logout
```

Generate a secure `ZITADEL_COOKIE_SECRET` with the built-in command for each framework:

| Framework | Command |
|-----------|---------|
| CodeIgniter 4 | `php spark zitadel:generate-secret` |
| Laravel | `php artisan zitadel:generate-secret` |
| Symfony | `php bin/console zitadel:generate-secret` |
| Phalcon / Yii | `php -r "echo bin2hex(random_bytes(32)) . PHP_EOL;"` |

The redirect URI is computed from `SERVER_URL + /zitadel/callback` in most
frameworks' config files. For CodeIgniter 4, the base class auto-derives it
from `SERVER_URL` when `ZITADEL_REDIRECT_URI` is not set. Register that URL
as the allowed callback in your Zitadel application settings.

`ZITADEL_PROTECT_ALL=true` is a CI4-specific env var (the other frameworks set
`protect_all` in their PHP/YAML config). Set it to require auth on every route.

The Zitadel application **must** be configured as a **User Agent** (public
PKCE client). No client secret is needed or used.

---

## `ZitadelConfig` — all options

| Constructor parameter | Type | Default | Notes |
|----------------------|------|---------|-------|
| `issuerUrl` | `string` | required | Must start with `https://` (or `http://localhost`) |
| `clientId` | `string` | required | |
| `redirectUri` | `string` | required | Full URL, e.g. `https://myapp.com/zitadel/callback` |
| `cookieSecret` | `string` | required | 64-char hex string (32 raw bytes) |
| `callbackPath` | `string` | `/zitadel/callback` | Path the middleware intercepts |
| `logoutPath` | `string` | `/zitadel/logout` | Path the middleware intercepts |
| `postLoginRedirect` | `string` | `/` | Relative path, after successful login |
| `postLogoutRedirect` | `string` | `/` | Relative path, sent to Zitadel as `post_logout_redirect_uri` |
| `protectAll` | `bool` | `false` | Require auth everywhere; opt out with `#[AllowAnonymous]` |
| `protectedRoutes` | `string[]` | `[]` | Routes requiring auth when `protectAll` is false; supports `prefix*` wildcards |
| `ignoredRoutes` | `string[]` | `[]` | Routes always skipped; takes precedence over `protectAll` |
| `scopes` | `string[]` | `['openid','profile','email']` | OAuth2 scopes to request |
| `allowedAlgorithms` | `Algorithm[]` | `[RS256, ES256]` | Accepted JWT signing algorithms |
| `allowedTokenTypes` | `TokenType[]` | `[JWT, at+JWT]` | Accepted `typ` header values |
| `audience` | `string\|array\|null` | `null` | Expected `aud` claim; `null` skips the check |
| `clockSkewSeconds` | `int` | `5` | Tolerance applied to `exp`, `nbf`, `iat` |
| `jwksTtlSeconds` | `int` | `300` | How long to cache JWKS public keys |
| `httpTimeoutSeconds` | `int` | `5` | cURL timeout for JWKS fetch and token exchange |
| `jwksPath` | `string` | `/oauth/v2/keys` | Relative path to JWKS endpoint |
| `authorizationPath` | `string` | `/oauth/v2/authorize` | Relative path to authorization endpoint |
| `tokenPath` | `string` | `/oauth/v2/token` | Relative path to token endpoint |
| `endSessionPath` | `string` | `/oidc/v1/end_session` | Relative path to logout endpoint |

---

## `#[AllowAnonymous]`

Apply to a controller class or method to exempt it from the auth check.
Named after ASP.NET Core's `[AllowAnonymous]` — `Public` is a PHP
reserved word.

```php
use Zitadel\Sdk\Attribute\AllowAnonymous;

#[AllowAnonymous]
class HomeController { … }
```

| Framework | Support | Mechanism |
|-----------|---------|-----------|
| Laravel | ✅ | Middleware inspects `$request->route()->getControllerClass()` |
| Symfony | ✅ | `KernelEvents::CONTROLLER` listener (after routing) |
| Phalcon MVC | ✅ | `dispatch:beforeDispatch` event |
| CodeIgniter 4 | ✅ | `service('router')->controllerName()` + reflection |
| Yii 3 | ✅ | `ZitadelMiddleware` reads the action class from the matched route |
| Slim 4 | ❌ | Use `ignoredRoutes` config instead |
| Phalcon Micro | ❌ | Routes are closures; use `ignoredRoutes` config instead |

---

## Laravel

### Install

```bash
composer require zitadel/sdk
```

The `ZitadelServiceProvider` is auto-discovered. No manual registration
needed.

### Configure — `config/zitadel.php`

```php
return [
    'issuer_url'           => env('ZITADEL_ISSUER_URL'),
    'client_id'            => env('ZITADEL_CLIENT_ID'),
    'redirect_uri'         => rtrim(env('SERVER_URL', 'http://localhost:3000'), '/') . '/zitadel/callback',
    'cookie_secret'        => env('ZITADEL_COOKIE_SECRET'),
    'post_login_redirect'  => env('ZITADEL_POST_LOGIN_URL', '/profile'),
    'post_logout_redirect' => env('ZITADEL_POST_LOGOUT_URL', '/'),
    'protect_all'          => true,
];
```

### Wire middleware — `bootstrap/app.php`

`ZitadelServiceProvider` registers a `zitadel()` macro on Laravel 11's
`Middleware` builder (mirrors Sanctum's `statefulApi()` pattern). Use it as a
one-liner — cookie-encryption exclusion is handled automatically:

```php
return Application::configure(basePath: dirname(__DIR__))
    ->withMiddleware(fn (Middleware $middleware) => $middleware->zitadel())
    ->create();
```

### Routes — `routes/web.php`

```php
Route::get('/', [HomeController::class, 'index'])->name('home');
Route::get('/profile', [ProfileController::class, 'show'])->name('profile');
```

### Controllers

```php
// Public route
use Zitadel\Sdk\Attribute\AllowAnonymous;

#[AllowAnonymous]
class HomeController extends Controller
{
    public function index(): View
    {
        return view('home');
    }
}

// Protected route — claims injected via ZitadelGuard
class ProfileController extends Controller
{
    public function show(): View
    {
        /** @var ZitadelUser $user */
        $user = auth('zitadel')->user();

        return view('profile', [
            'name'  => $user->claims->name,
            'email' => $user->claims->email,
            'sub'   => $user->claims->sub,
        ]);
    }
}
```

### Login / logout events

`ZitadelLoginEvent` fires in `CallbackController` after successful token
validation. `ZitadelLogoutEvent` fires in `LogoutController` before the
end-session redirect. Both use the standard Laravel `event()` helper:

```php
use Illuminate\Support\Facades\Event;
use Zitadel\Sdk\Event\ZitadelLoginEvent;
use Zitadel\Sdk\Event\ZitadelLogoutEvent;

// In AppServiceProvider::boot() or an EventServiceProvider:
Event::listen(ZitadelLoginEvent::class, function (ZitadelLoginEvent $event) {
    $claims = $event->claims;
    // Sync user record, update last_seen, log audit entry, etc.
    User::updateOrCreate(
        ['sub' => $claims->sub],
        ['name' => $claims->name, 'email' => $claims->email, 'last_login_at' => now()],
    );
});

Event::listen(ZitadelLogoutEvent::class, function (ZitadelLogoutEvent $event) {
    // Clean up user-specific state, write audit log, etc.
});
```

---

## Symfony

### Install

```bash
composer require zitadel/sdk
```

### Register bundle — `config/bundles.php`

```php
return [
    Symfony\Bundle\FrameworkBundle\FrameworkBundle::class => ['all' => true],
    Zitadel\Sdk\Bridge\Symfony\ZitadelBundle::class      => ['all' => true],
];
```

### Configure — `config/packages/zitadel.yaml`

```yaml
zitadel:
    issuer_url:            '%env(ZITADEL_ISSUER_URL)%'
    client_id:             '%env(ZITADEL_CLIENT_ID)%'
    redirect_uri:          '%env(SERVER_URL)%/zitadel/callback'
    cookie_secret:         '%env(ZITADEL_COOKIE_SECRET)%'
    protect_all:           true
    post_login_redirect:   '%env(ZITADEL_POST_LOGIN_URL)%'
    post_logout_redirect:  '%env(ZITADEL_POST_LOGOUT_URL)%'
```

No explicit middleware registration — `ZitadelBundle` registers the kernel
event listener automatically.

### Routes — `config/routes.yaml`

```yaml
home:
    path: /
    controller: App\Controller\HomeController::index

profile:
    path: /profile
    controller: App\Controller\ProfileController::show
```

### Controllers

```php
// Public route
use Zitadel\Sdk\Attribute\AllowAnonymous;

#[AllowAnonymous]
final class HomeController extends AbstractController
{
    #[Route('/', name: 'home')]
    public function index(): Response
    {
        return $this->render('home.html.twig');
    }
}

// Protected route — Claims auto-resolved by ClaimsValueResolver
use Zitadel\Sdk\Auth\Claims;

final class ProfileController extends AbstractController
{
    #[Route('/profile', name: 'profile')]
    public function show(Claims $claims): Response
    {
        return $this->render('profile.html.twig', [
            'name'  => $claims->name,
            'email' => $claims->email,
            'sub'   => $claims->sub,
        ]);
    }
}
```

`Claims` is injected directly as a controller argument via the
`ClaimsValueResolver` registered by the bundle. No request attribute
access needed.

### Login / logout events

`ZitadelListener` dispatches events via the PSR-14 `EventDispatcherInterface`
(injected automatically by Symfony's DI). Register listeners in the usual way:

```yaml
# config/services.yaml
App\EventListener\ZitadelLoginListener:
    tags:
        - { name: kernel.event_listener, event: Zitadel\Sdk\Event\ZitadelLoginEvent }
```

```php
use Zitadel\Sdk\Event\ZitadelLoginEvent;
use Zitadel\Sdk\Event\ZitadelLogoutEvent;

final class ZitadelLoginListener
{
    public function __invoke(ZitadelLoginEvent $event): void
    {
        $claims = $event->claims;
        // Sync user, update last_seen, audit log, etc.
    }
}
```

Or use `#[AsEventListener]`:

```php
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Zitadel\Sdk\Event\ZitadelLoginEvent;

#[AsEventListener]
final class ZitadelLoginListener
{
    public function __invoke(ZitadelLoginEvent $event): void
    {
        // $event->claims is the validated Claims object
    }
}
```

---

## Phalcon

### Install

```bash
composer require zitadel/sdk
```

Phalcon requires the `phalcon` PHP extension. It is **not** installable via
Nix `php@8.3` packages — use the Phalcon devbox configuration (see
`devbox.json` in `example-phalcon-auth`).

### Configure — `config/config.php`

Load `.env` manually with `vlucas/phpdotenv` (CI4 and Yii handle `.env`
natively; Phalcon does not):

```php
use Dotenv\Dotenv;

if (file_exists(dirname(__DIR__) . '/.env')) {
    Dotenv::createImmutable(dirname(__DIR__))->load();
}

return [
    'app' => [
        'serverUrl' => $_ENV['SERVER_URL']  ?? 'http://localhost:3000',
    ],
    'zitadel' => [
        'issuerUrl'    => $_ENV['ZITADEL_ISSUER_URL']     ?? '',
        'clientId'     => $_ENV['ZITADEL_CLIENT_ID']      ?? '',
        'cookieSecret' => $_ENV['ZITADEL_COOKIE_SECRET']  ?? '',
        'postLoginUrl' => $_ENV['ZITADEL_POST_LOGIN_URL'] ?? '/profile',
        'postLogoutUrl'=> $_ENV['ZITADEL_POST_LOGOUT_URL'] ?? '/',
    ],
];
```

### Bootstrap — `config/services.php`

Register Zitadel via the static service provider. `ZitadelConfig::fromArray()`
accepts a plain snake_case PHP array, removing the need to name every argument:

```php
use Phalcon\Di\DiInterface;
use Zitadel\Sdk\Bridge\Phalcon\ZitadelServiceProvider;
use Zitadel\Sdk\Config\ZitadelConfig;

return static function (DiInterface $di, array $config): void {
    // … session, view, router services …

    ZitadelServiceProvider::create($di, ZitadelConfig::fromArray([
        'issuer_url'          => $config['zitadel']['issuerUrl'],
        'client_id'           => $config['zitadel']['clientId'],
        'redirect_uri'        => rtrim($config['app']['serverUrl'], '/') . '/zitadel/callback',
        'cookie_secret'       => $config['zitadel']['cookieSecret'],
        'post_login_redirect' => $config['zitadel']['postLoginUrl'],
        'post_logout_redirect'=> $config['zitadel']['postLogoutUrl'],
        'protect_all'         => true,
    ]));
};
```

`ZitadelServiceProvider` implements `Phalcon\Di\ServiceProviderInterface` and
can be used with `$di->register(new ZitadelServiceProvider($config))` or the
`create()` static convenience alias. It registers `zitadelConfig`,
`zitadelValidator`, and `zitadelPlugin` in the DI container and attaches the
plugin to both the `application` and `dispatch` event managers automatically.

### Controllers

```php
// Public route
use Zitadel\Sdk\Attribute\AllowAnonymous;

#[AllowAnonymous]
final class HomeController extends Controller
{
    public function indexAction(): void
    {
        $this->view->pick('home/index');
    }
}

// Protected route — claims read from the DI container
use Zitadel\Sdk\Auth\Claims;

final class ProfileController extends Controller
{
    public function showAction(): void
    {
        /** @var Claims $claims */
        $claims = $this->di->get('zitadel.claims');

        $this->view->setVar('name',  $claims->name);
        $this->view->setVar('email', $claims->email);
        $this->view->setVar('sub',   $claims->sub);
        $this->view->pick('profile/show');
    }
}
```

### Login / logout events

`ZitadelPlugin` and `ZitadelMicroPlugin` fire events through Phalcon's events
manager — the same manager passed to `$eventsManager->attach('application', ...)`.
Attach your listener before the application handles the request:

```php
use Phalcon\Events\Event;
use Zitadel\Sdk\Event\ZitadelLoginEvent;
use Zitadel\Sdk\Event\ZitadelLogoutEvent;

$eventsManager->attach('zitadel:afterLogin', function (Event $event, mixed $source, ZitadelLoginEvent $loginEvent) {
    $claims = $loginEvent->claims;
    // Sync user, update last_seen, audit log, etc.
});

$eventsManager->attach('zitadel:afterLogout', function (Event $event, mixed $source, ZitadelLogoutEvent $logoutEvent) {
    // Clean up, audit log, etc.
});
```

---

## Yii 3

### Install

```bash
composer require zitadel/sdk
```

### Configure DI — `config/web/di.php`

Yii 3 uses a DI container. Wire `ZitadelConfig`, `JwksCache`,
`TokenValidator`, and `ZitadelMiddleware`:

```php
use Zitadel\Sdk\Auth\JwksCache;
use Zitadel\Sdk\Auth\JwksCacheInterface;
use Zitadel\Sdk\Auth\TokenValidator;
use Zitadel\Sdk\Bridge\Yii\ZitadelMiddleware;
use Zitadel\Sdk\Config\ZitadelConfig;

return [
    ZitadelConfig::class => [
        'class' => ZitadelConfig::class,
        '__construct()' => [
            'issuerUrl'          => $_ENV['ZITADEL_ISSUER_URL']     ?? '',
            'clientId'           => $_ENV['ZITADEL_CLIENT_ID']      ?? '',
            'redirectUri'        => rtrim($_ENV['SERVER_URL'] ?? 'http://localhost:3000', '/') . '/zitadel/callback',
            'cookieSecret'       => $_ENV['ZITADEL_COOKIE_SECRET']  ?? '',
            'postLoginRedirect'  => $_ENV['ZITADEL_POST_LOGIN_URL'] ?? '/profile',
            'postLogoutRedirect' => $_ENV['ZITADEL_POST_LOGOUT_URL'] ?? '/',
            'protectAll'         => true,
        ],
    ],

    JwksCacheInterface::class => JwksCache::class,
    JwksCache::class          => JwksCache::class,
    TokenValidator::class     => TokenValidator::class,
    ZitadelMiddleware::class  => ZitadelMiddleware::class,
];
```

### Bootstrap — `public/index.php`

Run `ZitadelMiddleware` around the entire application handler. **The
middleware must wrap the router** so `#[AllowAnonymous]` reflection works
after route matching:

```php
$container = new Container(ContainerConfig::create()->withDefinitions($diConfig));
$request   = (new ServerRequestCreator(…))->fromGlobals();

/** @var ZitadelMiddleware $zitadel */
$zitadel  = $container->get(ZitadelMiddleware::class);
$response = $zitadel->process($request, $appHandler);

http_response_code($response->getStatusCode());
foreach ($response->getHeaders() as $name => $values) {
    foreach ($values as $value) { header("{$name}: {$value}", false); }
}
echo $response->getBody();
```

### Routes — `config/web/application.php`

```php
use Zitadel\Sdk\Bridge\Yii\ZitadelMiddleware;
use Yiisoft\Router\Route;

return [
    'middlewares' => [ZitadelMiddleware::class],
    'routes' => [
        Route::get('/')->action(HomeAction::class)->name('home'),
        Route::get('/profile')->action(ProfileAction::class)->name('profile'),
    ],
];
```

### Actions

```php
// Public route
use Zitadel\Sdk\Attribute\AllowAnonymous;

#[AllowAnonymous]
final readonly class HomeAction
{
    public function __invoke(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        // render home view
    }
}

// Protected route — claims read from PSR-7 request attribute
use Zitadel\Sdk\Auth\Claims;

final readonly class ProfileAction
{
    public function __invoke(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        /** @var Claims $claims */
        $claims = $request->getAttribute('zitadel.claims');
        // render profile view with $claims->name, $claims->email, $claims->sub
    }
}
```

### Login / logout events

`ZitadelMiddleware` accepts an optional `?EventDispatcherInterface $eventDispatcher`
(PSR-14) as the fifth constructor argument. Wire it via Yii's DI config:

```php
use Psr\EventDispatcher\EventDispatcherInterface;
use Zitadel\Sdk\Bridge\Yii\ZitadelMiddleware;

// In config/web/di.php — add the dispatcher to the ZitadelMiddleware definition:
ZitadelMiddleware::class => [
    'class' => ZitadelMiddleware::class,
    '__construct()' => [
        // ... existing config, urlMatcher, responseFactory ...
        'eventDispatcher' => \Yiisoft\Definitions\Reference::to(EventDispatcherInterface::class),
    ],
],
```

Listen using Yii's standard PSR-14 event listener registration:

```php
use Zitadel\Sdk\Event\ZitadelLoginEvent;

// Your listener:
final class ZitadelLoginListener
{
    public function __invoke(ZitadelLoginEvent $event): void
    {
        $claims = $event->claims;
        // Sync user record, update last_seen, etc.
    }
}
```

---

## CodeIgniter 4

### Install

```bash
composer require zitadel/sdk
```

CI4 loads `.env` natively — no `vlucas/phpdotenv` required.

### Publish config stub

Run once to create `app/Config/Zitadel.php`:

```bash
php spark zitadel:publish
```

The generated file is an intentionally empty subclass. All settings come from
env vars; add properties only to hard-code values in PHP instead:

```php
namespace Config;
use Zitadel\Sdk\Bridge\CodeIgniter\Config\Zitadel as BaseZitadel;

// Override any property here, or leave empty and use .env only:
class Zitadel extends BaseZitadel {}
```

### Configure — `.env`

```dotenv
CI_ENVIRONMENT=development
SERVER_URL=http://localhost:3000       # derives redirect URI automatically
ZITADEL_ISSUER_URL=https://my.zitadel.cloud
ZITADEL_CLIENT_ID=your-client-id
ZITADEL_COOKIE_SECRET=<64-char-hex>   # php -r "echo bin2hex(random_bytes(32));"
ZITADEL_PROTECT_ALL=true              # require auth on every route
ZITADEL_POST_LOGIN_URL=/profile
ZITADEL_POST_LOGOUT_URL=/
```

The redirect URI is derived as `SERVER_URL + /zitadel/callback`. Set
`ZITADEL_REDIRECT_URI` explicitly to override.

No changes to `Services.php`, `Filters.php`, or `Routes.php` are needed:

- **Filter auto-registration** — `Config\Registrar` in the SDK registers `ZitadelFilter`
  as a global before-filter via CI4's Composer module discovery.
- **Self-configuration** — `ZitadelFilter` calls `config('Zitadel')` internally,
  resolving `app/Config/Zitadel.php` automatically.

### Routes — `app/Config/Routes.php`

Register only application routes. The callback and logout paths are handled by
the filter before any controller runs — no route entries needed for them:

```php
$routes->get('/', 'HomeController::index');
$routes->get('/profile', 'ProfileController::show');
```

### Controllers

```php
// Public route
use Zitadel\Sdk\Attribute\AllowAnonymous;

#[AllowAnonymous]
final class HomeController extends BaseController
{
    public function index(): string
    {
        return view('home/index');
    }
}

// Protected route — claims from ZitadelHolder (no PSR-7 request attributes in CI4)
use Zitadel\Sdk\Bridge\CodeIgniter\ZitadelHolder;

final class ProfileController extends BaseController
{
    public function show(): string
    {
        $claims = ZitadelHolder::claims();

        return view('profile/show', [
            'name'  => $claims?->name,
            'email' => $claims?->email,
            'sub'   => $claims?->sub,
        ]);
    }
}
```

CI4 does not use PSR-7 request attributes, so claims are accessed via the
static `ZitadelHolder::claims()` rather than `$request->getAttribute()`.

### Login / logout events

`ZitadelPreFilter` fires CI4 native events via `Events::trigger()`. Register
listeners in `app/Config/Events.php`:

```php
use CodeIgniter\Events\Events;
use Zitadel\Sdk\Event\ZitadelLoginEvent;
use Zitadel\Sdk\Event\ZitadelLogoutEvent;

Events::on('zitadel_login', function (ZitadelLoginEvent $event): void {
    $claims = $event->claims;
    // Sync user, update last_seen, write audit log, etc.
});

Events::on('zitadel_logout', function (ZitadelLogoutEvent $event): void {
    // Clean up, audit log, etc.
});
```

---

## Claims reference

| Property | Type | Description |
|----------|------|-------------|
| `$sub` | `string` | Subject — the user's unique Zitadel ID |
| `$name` | `string\|null` | Full display name |
| `$email` | `string\|null` | Email address |
| `$token` | `string` | Raw JWT — forward as `Authorization: Bearer $claims->token` |

All other claims from the JWT payload are accessible via `$claims->payload['custom_claim']`.

---

## Cookies set by the SDK

| Cookie | Purpose | TTL |
|--------|---------|-----|
| `__nextgen_auth` | Encrypted JWT access token | `exp - now` seconds |
| `__nextgen_pkce` | Encrypted PKCE verifier + state (in-flight only) | 600 seconds |

Both are `HttpOnly; SameSite=Lax`. The PKCE cookie is deleted immediately
after the callback is processed.

---

## JWT validation — what the SDK checks

Every request with a cookie or `Authorization: Bearer` header goes through
`TokenValidator::validate()`:

1. Exactly 3 segments (rejects JWE 5-segment tokens)
2. `alg` header present
3. `alg: none` rejected unconditionally (case-insensitive)
4. Algorithm is in `allowedAlgorithms`
5. `typ` header is in `allowedTokenTypes` (case-insensitive)
6. Public key fetched from JWKS (cached for `jwksTtlSeconds`)
7. Signature verified with `openssl_verify()` — EC signatures converted P1363 → DER
8. `iss` matches `issuerUrl` exactly
9. `aud` intersects expected audience (if configured)
10. `exp` not in the past (±`clockSkewSeconds`)
11. `nbf` not in the future (±`clockSkewSeconds`, if present)
12. `iat` not in the future (±`clockSkewSeconds`, if present)
13. `sub` present and non-empty

Returns `null` on any failure — never throws. The middleware treats `null`
as unauthenticated and redirects to login.

---

## Tooling

```bash
composer test       # PHPUnit with coverage
composer phpstan    # static analysis
composer format     # php-cs-fixer
composer rector     # Rector upgrades
composer depcheck   # composer-unused
composer dev        # built-in PHP server on $PORT (default 3000)
```
