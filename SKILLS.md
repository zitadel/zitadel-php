# Integrating zitadel/zitadel-php

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
ZITADEL_COOKIE_SECRET="…"                   # 64-char hex — php -r "echo bin2hex(random_bytes(32));"
ZITADEL_POST_LOGIN_URL="/profile"           # where to send the user after login
ZITADEL_POST_LOGOUT_URL="/"                 # where to send the user after logout
```

`ZITADEL_REDIRECT_URI` is **not** an env var. The redirect URI is always
computed as `SERVER_URL + /zitadel/callback`. Register that exact URL as
the allowed callback in your Zitadel application settings.

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
| CodeIgniter 4 | ✅ | `service('router')->getController()` + reflection |
| Yii 3 | ✅ | `ZitadelMiddleware` reads the action class from the matched route |
| Slim 4 | ❌ | Use `ignoredRoutes` config instead |
| Phalcon Micro | ❌ | Routes are closures; use `ignoredRoutes` config instead |

---

## Laravel

### Install

```bash
composer require zitadel/zitadel-php
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

Add `ZitadelMiddleware` to the `web` group and exclude the PKCE cookies
from Laravel's cookie encryption (the SDK encrypts them itself):

```php
use Zitadel\Sdk\Bridge\Laravel\Http\Middleware\ZitadelMiddleware;
use Illuminate\Session\Middleware\StartSession;
use Illuminate\View\Middleware\ShareErrorsFromSession;
use Illuminate\Foundation\Http\Middleware\ValidateCsrfToken;

return Application::configure(basePath: dirname(__DIR__))
    ->withMiddleware(function (Middleware $middleware) {
        $middleware->web(append: [
            StartSession::class,
            ShareErrorsFromSession::class,
            ValidateCsrfToken::class,
            ZitadelMiddleware::class,
        ]);
        $middleware->encryptCookies(except: ['__nextgen_pkce', '__nextgen_auth']);
    })->create();
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

---

## Symfony

### Install

```bash
composer require zitadel/zitadel-php
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

---

## Phalcon

### Install

```bash
composer require zitadel/zitadel-php
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

### Bootstrap — `public/index.php`

Build `ZitadelConfig`, construct `ZitadelPlugin`, and attach it to both
the `application` and `dispatch` event managers:

```php
use Zitadel\Sdk\Auth\JwksCache;
use Zitadel\Sdk\Auth\TokenValidator;
use Zitadel\Sdk\Bridge\Phalcon\ZitadelPlugin;
use Zitadel\Sdk\Config\ZitadelConfig;
use Phalcon\Events\Manager as EventsManager;
use Phalcon\Mvc\Application;
use Phalcon\Mvc\Dispatcher;

$config = require dirname(__DIR__) . '/config/config.php';
$di     = new FactoryDefault();

$zitadelConfig = new ZitadelConfig(
    issuerUrl:          $config['zitadel']['issuerUrl'],
    clientId:           $config['zitadel']['clientId'],
    redirectUri:        rtrim($config['app']['serverUrl'], '/') . '/zitadel/callback',
    cookieSecret:       $config['zitadel']['cookieSecret'],
    postLoginRedirect:  $config['zitadel']['postLoginUrl'],
    postLogoutRedirect: $config['zitadel']['postLogoutUrl'],
    protectAll:         true,
);
$plugin = new ZitadelPlugin($zitadelConfig, new TokenValidator($zitadelConfig, new JwksCache()));

$eventsManager = new EventsManager();
$eventsManager->attach('application', $plugin);
$eventsManager->attach('dispatch',    $plugin);

$di->setShared('dispatcher', function () use ($eventsManager) {
    $dispatcher = new Dispatcher();
    $dispatcher->setDefaultNamespace('App\\Controllers');
    $dispatcher->setEventsManager($eventsManager);
    return $dispatcher;
});

$application = new Application($di);
$application->setEventsManager($eventsManager);

// ZitadelPlugin may short-circuit the request (redirect / callback) and
// return false from handle(). Guard before calling send().
$result = $application->handle($_SERVER['REQUEST_URI']);
if ($result !== false) {
    $result->send();
}
```

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

---

## Yii 3

### Install

```bash
composer require zitadel/zitadel-php
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

---

## CodeIgniter 4

### Install

```bash
composer require zitadel/zitadel-php
```

CI4 loads `.env` natively — no `vlucas/phpdotenv` required. Use CI4's
`env()` helper everywhere; **do not** read from `$_ENV` directly.

CI4's filter system instantiates filter classes with `new ClassName()` —
no constructor injection. The solution is a thin wrapper that pulls from
the `Services` container.

### Configure — `app/Config/Services.php`

```php
use Zitadel\Sdk\Auth\JwksCache;
use Zitadel\Sdk\Auth\TokenValidator;
use Zitadel\Sdk\Config\ZitadelConfig;

class Services extends BaseServices
{
    public static function zitadelConfig(bool $getShared = true): ZitadelConfig
    {
        if ($getShared) {
            return static::getSharedInstance('zitadelConfig');
        }

        $serverUrl = rtrim((string) env('SERVER_URL', 'http://localhost:3000'), '/');

        return new ZitadelConfig(
            issuerUrl:          (string) env('ZITADEL_ISSUER_URL', ''),
            clientId:           (string) env('ZITADEL_CLIENT_ID', ''),
            redirectUri:        $serverUrl . '/zitadel/callback',
            cookieSecret:       (string) env('ZITADEL_COOKIE_SECRET', ''),
            postLoginRedirect:  (string) env('ZITADEL_POST_LOGIN_URL', '/profile'),
            postLogoutRedirect: (string) env('ZITADEL_POST_LOGOUT_URL', '/'),
            protectAll:         true,
        );
    }

    public static function zitadelValidator(bool $getShared = true): TokenValidator
    {
        if ($getShared) {
            return static::getSharedInstance('zitadelValidator');
        }

        return new TokenValidator(
            static::zitadelConfig(false),
            new JwksCache(),
        );
    }
}
```

### Filter wrapper — `app/Filters/ZitadelFilterWrapper.php`

```php
use CodeIgniter\Filters\FilterInterface;
use Config\Services;
use Zitadel\Sdk\Bridge\CodeIgniter\ZitadelFilter;

final readonly class ZitadelFilterWrapper implements FilterInterface
{
    private ZitadelFilter $inner;

    public function __construct()
    {
        $this->inner = new ZitadelFilter(
            Services::zitadelConfig(false),
            Services::zitadelValidator(false),
        );
    }

    public function before(RequestInterface $request, $arguments = null): ?ResponseInterface
    {
        return $this->inner->before($request, $arguments);
    }

    public function after(RequestInterface $request, ResponseInterface $response, $arguments = null): ResponseInterface
    {
        return $this->inner->after($request, $response, $arguments);
    }
}
```

### Register globally — `app/Config/Filters.php`

```php
use App\Filters\ZitadelFilterWrapper;

class Filters extends BaseConfig
{
    public array $aliases = ['zitadel' => ZitadelFilterWrapper::class];
    public array $globals = ['before' => ['zitadel'], 'after' => []];
}
```

### Routes — `app/Config/Routes.php`

The PKCE callback and logout paths must be registered as routes so CI4
runs before-filters on them. The controller is never actually reached for
those paths — `ZitadelFilter` intercepts and responds first.

```php
$routes->get('/', 'HomeController::index');
$routes->get('/profile', 'ProfileController::show');
$routes->get('/zitadel/callback', 'ZitadelController::callback');
$routes->get('/zitadel/logout',   'ZitadelController::logout');
$routes->set404Override('HomeController::notFound');
```

### `.env` — set `CI_ENVIRONMENT`

CI4 **requires** `CI_ENVIRONMENT` to be set. Without it the framework
defaults to `production` and fails to boot in a dev environment:

```dotenv
CI_ENVIRONMENT=development
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
