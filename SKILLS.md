# SKILLS — Zitadel PHP SDK

## What this is

PKCE + JWT auth middleware for PHP 8.3+. No sessions; all state in cookies.

## Key concepts

- `ZitadelConfig` — single immutable config; all options described below
- `ZitadelMiddleware` (PSR-15) — owns the full lifecycle: PKCE redirect, callback,
  logout, token validation, route protection
- `Claims` — readonly object attached to the request after successful token validation

## Configuration reference (all options)

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `issuerUrl` | `string` | — | Zitadel instance URL, e.g. `https://my.zitadel.cloud` |
| `clientId` | `string` | — | OAuth2 client ID |
| `redirectUri` | `string` | — | Full callback URL, e.g. `https://myapp.com/zitadel/callback` |
| `cookieSecret` | `string` | — | 64-char hex string for PKCE state cookie encryption |
| `callbackPath` | `string` | `/zitadel/callback` | Path the middleware intercepts for token exchange |
| `logoutPath` | `string` | `/zitadel/logout` | Path the middleware intercepts to clear session |
| `postLoginRedirect` | `string` | `/` | Where to redirect after successful login |
| `postLogoutRedirect` | `string` | `/` | Where to redirect after logout |
| `protectAll` | `bool` | `false` | Protect all routes; use `ignoredRoutes` or `#[AllowAnonymous]` to opt out |
| `protectedRoutes` | `string[]` | `[]` | Paths requiring auth (when `protectAll` is false); supports `prefix*` wildcards |
| `ignoredRoutes` | `string[]` | `[]` | Paths skipped entirely (no token check); takes precedence over `protectAll` |
| `scopes` | `string[]` | `['openid', 'profile', 'email']` | OAuth2 scopes requested |
| `allowedAlgorithms` | `Algorithm[]` | `[RS256, ES256]` | Accepted JWT signing algorithms |
| `allowedTokenTypes` | `TokenType[]` | `[JWT, at+JWT]` | Accepted JWT `typ` header values |
| `audience` | `string\|array\|null` | `null` | Expected `aud` claim; `null` skips check |
| `clockSkewSeconds` | `int` | `5` | Tolerance for `exp`/`nbf`/`iat` clock skew |
| `jwksTtlSeconds` | `int` | `300` | JWKS key cache TTL |
| `httpTimeoutSeconds` | `int` | `5` | Timeout for JWKS fetch and token exchange |

## Accessing claims

| Framework | Access pattern |
|-----------|----------------|
| Laravel | `auth()->user()->claims` or `auth('zitadel')->user()->claims` |
| Symfony | `?Claims $claims` controller parameter (auto-resolved by `ClaimsValueResolver`) |
| Yii 3, Slim 4, Mezzio | `$request->getAttribute('zitadel.claims')` |
| Phalcon Micro | `$app->getDI()->get('zitadel.claims')` |
| Phalcon MVC | `$this->di->get('zitadel.claims')` |
| CodeIgniter 4 | `ZitadelHolder::claims()` (static — no request attributes in CI4) |

HttpFoundation fallback (Laravel + Symfony):
```php
$claims = $request->attributes->get('zitadel.claims'); // Claims|null
```

Forwarding token to downstream services (all frameworks):
```php
'Authorization' => 'Bearer ' . $claims->token
```

## Framework setup quick ref

- **Laravel**: zero config — ServiceProvider auto-discovered; middleware in `web` group automatically
- **Symfony**: add bundle + `zitadel.yaml`; `ClaimsValueResolver` auto-registers
- **Yii 3**: bind `ZitadelConfig` in DI; add `ZitadelMiddleware` before `Router`
- **Slim 4**: `$app->add(new ZitadelMiddleware(...))` — PSR-15 native, no bridge
- **Mezzio**: `$app->pipe(new ZitadelMiddleware(...))` — PSR-15 native, no bridge
- **CodeIgniter 4**: register `ZitadelFilter` alias + global before; `ZitadelHolder::claims()` in controllers
- **Phalcon Micro**: `$app->before(new ZitadelMicroPlugin(...))`
- **Phalcon MVC**: attach `ZitadelPlugin` to `application:beforeHandleRequest` + `dispatch:beforeDispatch`

## `#[AllowAnonymous]` attribute

Apply to a controller method or class to skip auth on that handler. Named after
ASP.NET Core's `[AllowAnonymous]` — `Public` is a PHP reserved keyword.

| Framework | Support |
|-----------|---------|
| Symfony | Full — `KernelEvents::CONTROLLER` listener (after routing) |
| Laravel | Full — web-group middleware + `$request->route()->getControllerClass()` |
| CodeIgniter 4 | Full — `service('router')->getController()` + reflection |
| Mezzio | Full — add `ZitadelMiddleware` AFTER `RouteMiddleware` |
| Yii 3 | Full — add `ZitadelMiddleware` AFTER `Router` middleware |
| Phalcon MVC | Full — `dispatch:beforeDispatch` event |
| Slim 4 | **Not supported** — use `ignoredRoutes` |
| Phalcon Micro | **Not supported** — routes are closures; use `ignoredRoutes` |

## Security invariants (never change these)

- JWT must have exactly 3 segments (rejects JWE 5-segment tokens)
- `alg` header field must be present — missing → null
- `alg:none` always rejected unconditionally (before JWKS fetch, case-insensitive)
- JWKS key selection filters by `"use":"sig"` to avoid picking an encryption key
- `iss` validated with strict string equality against `issuerUrl`
- Bearer header takes precedence over cookie when both present
- PKCE verifier and state generated with `random_bytes(32)` → 256 bits entropy
- PKCE cookie deleted immediately on use (before code exchange)
- `state` param validated against `__nextgen_pkce` cookie; mismatch → 400 (CSRF)
- `$next` validated: starts with `/`, not `//`, no backslash, no scheme — blocks open-redirect
- Exchanged access token validated via `TokenValidator` BEFORE setting `__nextgen_auth` cookie
- `issuerUrl` must use `https://` (localhost exempt)
- `cookieSecret`: 64-char hex string, validated to exactly 32 bytes via `hex2bin`
- cURL SSL peer verification always enabled
- `sub` must be present in validated token (`Claims::$sub` is non-nullable)
- Stale `__nextgen*` cookies deleted on public unauthenticated routes
- Logout with no session: silently redirect — never return 400

## Cookie reference

| Cookie | Content | TTL |
|--------|---------|-----|
| `__nextgen_auth` | JWT access token | `Max-Age = int(exp - time())` |
| `__nextgen_pkce` | Encrypted JSON `{verifier, state, next}` | `Max-Age = 600` |

## Tooling

```bash
composer test        # PHPUnit (tests + specs)
composer phpstan     # Static analysis
composer format      # php-cs-fixer
composer rector      # Rector upgrades
composer docgen      # PHPDoc generation
composer depcheck    # composer-unused
```
