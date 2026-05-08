# AGENTS — zitadel/sdk

AI agent guide for the `zitadel/sdk` PHP library. Read this before touching any code.

---

## What this is

PKCE + JWT authentication middleware for PHP 8.3+. Handles the full OAuth 2.0 Authorization
Code + PKCE flow, validates JWTs via JWKS, stores all session state in encrypted HttpOnly
cookies, and exposes authenticated claims to controllers. No server-side sessions, no custom
routes in user apps, no external runtime dependencies.

---

## Project structure

```
lib/           # All production code — namespace Zitadel\Sdk\
test/          # Unit tests — namespace Zitadel\Sdk\Test\
spec/          # Integration specs (Testcontainers + real Zitadel) — namespace Zitadel\Sdk\Spec\
docs/          # PHPDoc guide pages (framework guides, index)
```

Structure mirrors `zitadel/client-php` exactly: same tooling, same CI workflows, same
directory layout, same license (Apache-2.0).

---

## Immutability rules

Every class must be as immutable as possible. There are exactly two documented exceptions.

| Class | Declaration | Rule |
|-------|-------------|------|
| Static utilities (`PkceFlow`, `PkceStateCookie`, `JwkConverter`) | `final class` + `private __construct()` | No instantiation; all methods static |
| Value objects and service classes | `readonly class` | Constructor-promoted properties only; no mutation after construction |
| Framework adapter (CI4 filter) | `final readonly class` | `FilterInterface` is a pure interface — `readonly` is compatible |
| Framework adapters over mutable parents (`ZitadelServiceProvider`, `ZitadelBundle`, `ZitadelExtension`) | `final class` | Parent is mutable; no properties added |
| Exceptions (`TokenValidationException`, `PkceException`) | `final class` | `RuntimeException` is a mutable parent |
| Constants class (`Version`) | `final class` | Single typed `const`; no instantiation |
| `JwksCache` | `final class` | **Mutable exception 1.** `private static array $store` caches JWKS keys in-process. Mirrors the TypeScript module-level `Map`. Intentional for performance. |
| `ZitadelHolder` (CI4 only) | `final class` | **Mutable exception 2.** CI4 has no request-attribute system. `private static ?Claims $current` is the only way to pass claims from a `FilterInterface` to a controller without server-side sessions. |
| `ZitadelGuard` (Laravel) | `class` | Implements `Guard`; `private ?ZitadelUser $user` is mutable by contract (`setUser()` is required by Laravel). Not `final` — standard Laravel guards (`SessionGuard`, `TokenGuard`) are not final, and users need to be able to override for `actingAs()` in tests. |

**Rule**: if a class can be `readonly class`, it must be. If it cannot (mutable parent,
interface contract), it is `final class`. If it must be extensible (guard), it is `class`.
No other variation is allowed without updating this file and the plan.

---

## PHP version requirements

Minimum: **PHP 8.3**. Use PHP 8.0–8.3 features throughout — never fall back to older patterns.

| Feature | Version | Where used |
|---------|---------|-----------|
| `#[\Override]` | 8.3 | Every interface/abstract method implementation |
| Typed class constants | 8.3 | `Version::VERSION`, enum backing values, interface constants |
| `json_validate()` | 8.3 | Before every `json_decode()` call |
| `#[\SensitiveParameter]` | 8.2 | All secret/token parameters: `$cookieSecret`, `$secret`, `$token` |
| `readonly class` | 8.2 | All value objects and service classes |
| `readonly` property | 8.1 | Individual immutability where `readonly class` is blocked |
| `array_is_list()` | 8.1 | Validate route array inputs |
| `new` in initializers | 8.1 | Default Algorithm/TokenType arrays in ZitadelConfig |
| `match` expression | 8.0 | Exhaustive matching (fatal on unhandled case) |
| `str_starts_with()` / `str_ends_with()` / `str_contains()` | 8.0 | All string checks — never `strpos()` |
| `enum` | 8.1 | `Algorithm`, `TokenType` |

`#[\Override]` applies to every method that implements an interface or overrides a parent:
`ZitadelUser` (all `Authenticatable` methods), `ZitadelGuard` (all `Guard` methods),
`ZitadelMiddleware::handle()` (Laravel), `ZitadelBundle::build()`, `ZitadelExtension::load()`,
`Configuration::getConfigTreeBuilder()`, `ZitadelListener::onKernelRequest()`,
`ZitadelListener::onKernelController()`, `ClaimsValueResolver::resolve()`,
`ZitadelMicroPlugin::call()`, `ZitadelMiddleware::process()` (PSR-15),
`ZitadelFilter::before()` / `ZitadelFilter::after()`,
`ZitadelPlugin::beforeHandleRequest()` / `ZitadelPlugin::beforeDispatch()`,
and exception constructors.

---

## Security invariants — never change these

1. JWT must have exactly 3 dot-separated segments. Reject anything else (4 segments =
   unsupported JWE; 2 = malformed).
2. `alg` header field must be present. Missing → null (never fall through to JWKS fetch).
3. `alg: none` is rejected unconditionally, case-insensitive, before any JWKS fetch.
4. JWKS key selection filters by `"use":"sig"` to avoid picking an encryption key.
5. `iss` validated with strict string equality against `$issuerUrl`. No normalization.
6. Bearer header wins over cookie when both are present.
7. PKCE verifier and state generated with `random_bytes(32)` → 256-bit entropy.
8. PKCE cookie deleted immediately on callback before code exchange (single-use).
9. `state` param validated against `__nextgen_pkce` cookie before code exchange.
   Mismatch → 400 (CSRF). Never redirect on mismatch.
10. `$next` open-redirect guard: must start with `/`, must not start with `//`, must not
    contain a backslash after the leading `/`, and `parse_url($next, PHP_URL_SCHEME)`
    must return `null`. Blocks `/\evil.com` and `/%09http://` vectors.
11. Exchanged access token MUST be validated via `TokenValidator::validate()` before the
    `__nextgen_auth` session cookie is set. Never store an unvalidated token.
12. OAuth error response inspected: `error` field → `PkceException` with `error_description`.
13. `issuerUrl` must use `https://`. HTTP is only allowed for `localhost` and `127.x`.
14. `issuerUrl` must not end with `/.well-known/openid-configuration`.
15. `cookieSecret` must be a 64-character hex string. Validated via `hex2bin()` to exactly
    32 raw bytes (XChaCha20-Poly1305 key size). Generate: `bin2hex(random_bytes(32))`.
16. cURL SSL peer verification is always `true`. Never set `CURLOPT_SSL_VERIFYPEER = false`.
17. `Secure` cookie flag set only via the framework's native HTTPS detection method —
    never via `$_SERVER['HTTPS']` directly (breaks behind TLS-terminating proxies).
18. `sub` must be present and non-empty in validated token (`Claims::$sub` is non-nullable).
19. Stale `__nextgen*` cookies (all names starting with `__nextgen`) are deleted on every
    unauthenticated public route response.
20. Logout with no session: silently redirect to `$postLogoutRedirect`. Never return 400.

---

## Framework idiom rules

### Universal

- Every framework integration intercepts callback and logout paths **before** routing.
  No user app needs to add any routes.
- Claims are passed to controllers via the framework's native request-scoped mechanism.
  Never use `$_REQUEST`, superglobals, or session.
- `Bearer` header wins over cookie when both present — consistent across all frameworks.

### Laravel

- `ZitadelServiceProvider` follows the Passport/Sanctum pattern: `loadRoutesFrom()` for
  internal routes (route-cache compatible), `pushMiddlewareToGroup('web', ...)` for the
  middleware, `publishes(...)` for the config template.
- The Illuminate middleware runs in the `web` group (not global) so that
  `$request->route()->getControllerClass()` is available when it fires.
- `ZitadelGuard` is registered via `Auth::extend('zitadel', ...)`. Controllers use
  `auth('zitadel')->user()` or `auth()->user()` (if set as default guard).
- Route protection is done via `ZitadelConfig` (`protectedRoutes` / `protectAll: true`),
  NOT via `->middleware('auth:zitadel')` on routes. The `auth:zitadel` guard middleware
  redirects to `route('login')`, not to Zitadel — it is for API Bearer-token flows only.
- Opt-out from auth:
  - **Native Laravel**: `->withoutMiddleware(ZitadelMiddleware::class)` on the route
  - **Library convenience**: `#[AllowAnonymous]` on a controller method or class
  - Both must be documented; neither takes precedence over the other.
- Do NOT integrate with `symfony/security-bundle` or any security-bundle equivalent.

### Symfony

- Use `KernelEvents::REQUEST` (priority 8) for PKCE flow and token validation. This fires
  before the router (priority -32). Do NOT use `AbstractAuthenticator` or Symfony Firewall
  integration — this library is a standalone PKCE middleware, not a Security Bundle
  authenticator. A future v2 could add optional Security Bundle integration.
- Use `KernelEvents::CONTROLLER` (priority 0) for `#[AllowAnonymous]` reflection (fires
  after routing resolves the controller).
- `ClaimsValueResolver implements ValueResolverInterface` with `#[AutoconfigureTag]` is
  the idiomatic Symfony 6+ way to inject custom request-derived values into controllers.
  This is the same pattern Symfony uses for `#[CurrentUser]` / `UserValueResolver`.
- `$request->attributes->set('zitadel.claims', $claims)` — always set before passing to
  the next handler. This is how Symfony passes data between listeners and controllers.
- `ZitadelBundle extends Bundle` (not `AbstractBundle`) for broad Symfony 5/6/7 compat.
- Config tree builder in `Configuration implements ConfigurationInterface` with a
  `ZitadelExtension extends Extension` — standard Bundle DI extension pattern.

### Yii 3

- Pure PSR-15: `ZitadelMiddleware` is added to the pipeline before `Router::class`. No
  bridge classes needed beyond a `ZitadelBootstrap` for DI wiring.
- Claims are accessed via `$request->getAttribute('zitadel.claims')` — this is the
  PSR-7 standard for request-scoped data.
- `#[AllowAnonymous]` works by placing `ZitadelMiddleware` AFTER the `Router` middleware
  so the matched action's request attribute is available for reflection.

### CodeIgniter 4

- `ZitadelFilter implements FilterInterface` — the standard CI4 hook for pre-routing
  intercepts. `before()` returns a `ResponseInterface` to short-circuit dispatch.
- CI4 has no PSR-7 request attributes. `ZitadelHolder` (static) is the only way to pass
  validated claims from a filter to a controller within the same process lifecycle.
  This is documented as the second mutable exception.
- Register as a global filter in `app/Config/Filters.php`.
- Use `service('router')->getController()` (returns FQCN) for `#[AllowAnonymous]`
  reflection — NOT `service('router')->controllerName()` which returns only a short name.

### Slim 4 / Mezzio

- PSR-15 native. No bridge classes. `ZitadelMiddleware` is used directly.
- `$app->add(new ZitadelMiddleware(...))` for Slim; `$app->pipe(...)` for Mezzio.
- `#[AllowAnonymous]` is NOT supported for Slim 4: ZitadelMiddleware must run before
  routing to intercept callback/logout (no Slim routes are registered for them). Use
  `ignoredRoutes` instead.

### Phalcon MVC

- `ZitadelPlugin` attaches to TWO events:
  - `application:beforeHandleRequest` — fires before routing; handles PKCE flow, logout,
    token validation. Returns `false` to short-circuit.
  - `dispatch:beforeDispatch` — fires after dispatcher resolves controller+action; used
    for `#[AllowAnonymous]` reflection.
- Claims are registered in the DI container under `'zitadel.claims'` and accessed via
  `$this->di->get('zitadel.claims')` in controllers.
- User's `public/index.php` must handle `false` return: `if ($result !== false) { ... }`.

### Phalcon Micro

- `ZitadelMicroPlugin implements MiddlewareInterface` — registered via `$app->before(...)`.
- `#[AllowAnonymous]` is NOT supported: Micro routes are typically closures, and PHP
  attributes cannot be placed on closures. Use `ignoredRoutes` instead.

---

## Cross-framework harmony

The goal is that once a developer understands how the library works in one framework,
every other framework feels familiar. Enforce these invariants across all bridges:

| Concern | Rule |
|---------|------|
| Claims access | HttpFoundation (Laravel + Symfony): `$request->attributes->get('zitadel.claims')`. PSR-7 (Yii 3, Slim 4, Mezzio, Phalcon Micro): `$request->getAttribute('zitadel.claims')`. CI4 only: `ZitadelHolder::claims()`. Phalcon MVC only: `$this->di->get('zitadel.claims')`. |
| HTTPS detection | PSR-7: `$request->getUri()->getScheme() === 'https'`. Laravel/Symfony/CI4: `$request->isSecure()`. Phalcon MVC: `$this->request->isSecure()`. Never use `$_SERVER['HTTPS']`. |
| Token preference | Bearer header over cookie, in all bridges, always. |
| Cookie deletion | All `__nextgen*` cookies deleted on every public unauthenticated response. |
| Error on callback failure | 400 with minimal HTML. Not JSON, not empty, not a redirect. |
| Logout with no session | Silent redirect to `$postLogoutRedirect`. Never 400. |
| Token forwarding | `$claims->token` is the raw signed JWT. Forward as `Authorization: Bearer {$claims->token}` to downstream services. |
| Idiomatic shortcut | Laravel: `auth()->user()->claims`. Symfony: `?Claims $claims` controller param. All others: request attribute. |

---

## DX guidelines

1. **Zero routes in user apps.** The middleware intercepts `/zitadel/callback` and
   `/zitadel/logout` before routing. Users never add routes.
2. **One config object.** `ZitadelConfig` holds everything. Construct once, share as
   singleton. All options have sensible defaults.
3. **Secure by default.** Lead all docs with `protectAll: true`. Document `protectedRoutes`
   as the alternative for apps where most routes are public.
4. **`Claims` is the single source of truth.** All frameworks attach a `Claims` object (or
   null) to the request. The object includes `$token` for downstream forwarding.
5. **Error messages must be actionable.** `ZitadelConfig` constructor guards throw
   `\InvalidArgumentException` with a message that names the parameter, describes what's
   wrong, and shows the fix (e.g. "Generate with: `bin2hex(random_bytes(32))`").
6. **Framework idioms over consistency.** Each bridge must feel native to its framework.
   Do not sacrifice idiomatic patterns for uniformity with other bridges.

---

## Namespace

All production classes: `Zitadel\Sdk\` (autoloaded from `lib/`).
Tests: `Zitadel\Sdk\Test\` (`test/`).
Integration specs: `Zitadel\Sdk\Spec\` (`spec/`).

---

## Cookies

| Cookie | Content | TTL | Flags |
|--------|---------|-----|-------|
| `__nextgen_auth` | JWT access token | `Max-Age = int(exp - time())` | HttpOnly, SameSite=Lax, Secure on HTTPS |
| `__nextgen_pkce` | XChaCha20-Poly1305 encrypted `{verifier, state, next}` | `Max-Age = 600` | HttpOnly, SameSite=Lax, Secure on HTTPS |

`__nextgen_pkce` encrypted with `sodium_crypto_aead_xchacha20poly1305_ietf_encrypt()`.
24-byte random nonce prepended, result base64url-encoded. Key = `hex2bin($cookieSecret)`.

---

## PKCE state cookie encryption

Two-layer design in `PkceStateCookie`:

- **Lower layer** (`encrypt` / `decrypt`): pure string I/O; no HTTP objects. Framework
  bridges that cannot use PSR-7 (Laravel, Symfony, Phalcon MVC) call these directly.
- **Upper layer** (`write` / `read` / `delete`): PSR-7 convenience wrappers used by the
  PSR-15 core middleware and Yii 3.

---

## JWT validation order (15 steps)

`TokenValidator::validate()` must follow this exact order:

1. Split token at `.` — exactly 3 segments (≠3 → null)
2. Base64url-decode header segment — `=== false` guard
3. Base64url-decode payload segment — `=== false` guard
4. `json_validate()` + `json_decode()` header; `json_validate()` + `json_decode()` payload
5. Require `alg` field present in header — missing → null
6. Reject `alg: none` unconditionally (case-insensitive)
7. Map `alg` to `Algorithm` via `Algorithm::tryFrom()` — unknown → null
8. Reject if algorithm not in `$allowedAlgorithms`
9. Validate `typ` header (case-insensitive) against `$allowedTokenTypes`
10. Fetch public key via `JwksCache::getPublicKey()` (filters `"use":"sig"`) — null → null
11. Verify signature with `openssl_verify()`. EC signatures: convert IEEE P1363 → DER first.
12. Validate `iss` strict string equality against `$issuerUrl`
13. Validate `aud` if `$audience` is set
14. Validate `exp` (must be in the future, minus clock skew)
15. Validate `nbf` if present (must be in the past, plus clock skew)
16. Validate `iat` if present (must not be in the future, plus clock skew)
17. Require `sub` present and non-empty — missing → null
18. Return `Claims` (including `$token` = raw signed JWT string). Any failure returns null; never throws.

---

## Tooling

Mirrors `zitadel/client-php` exactly. Run:

```
composer test      # PHPUnit (unit + integration specs)
composer phpstan   # PHPStan static analysis
composer format    # php-cs-fixer
composer rector    # Rector modernisation
composer docgen    # phpdocumentor
composer depcheck  # composer-unused
```
