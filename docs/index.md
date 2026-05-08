# Zitadel PHP SDK

Zero-dependency PKCE authentication middleware for PHP 8.3+. Handles the full
OAuth 2.0 Authorization Code + PKCE flow, validates JWTs via JWKS, stores all
session state in encrypted HttpOnly cookies, and exposes authenticated claims to
controllers — no server-side sessions, no custom routes.

## Framework Guides

- [Laravel](laravel.md) — Auto-discovered ServiceProvider, Auth guard, `auth()->user()`
- [Symfony](symfony.md) — Bundle + EventListener, `?Claims $claims` controller injection
- [Yii 3](yii.md) — PSR-15 middleware pipeline, `$request->getAttribute('zitadel.claims')`
- [Slim 4](slim.md) — PSR-15 native, no bridge, `$app->add(...)`
- [Mezzio](mezzio.md) — PSR-15 native, no bridge, `$app->pipe(...)`
- [CodeIgniter 4](codeigniter.md) — FilterInterface, `ZitadelHolder::claims()`
- [Phalcon](phalcon.md) — Micro MiddlewareInterface / MVC beforeHandleRequest, DI service

## Architecture

The library has three layers:

1. **Core** (`lib/Auth/`, `lib/Middleware/`) — pure PSR-15, zero framework dependencies
2. **Bridges** (`lib/Bridge/`) — thin, idiomatic adapters per framework
3. **Config** (`lib/Config/ZitadelConfig`) — single immutable config object

## Quick Start

1. Install: `composer require zitadel/zitadel-php`
2. Set environment variables:
   - `ZITADEL_ISSUER_URL` — your Zitadel instance URL, e.g. `https://my.zitadel.cloud`
   - `ZITADEL_CLIENT_ID` — OAuth 2.0 client ID
   - `ZITADEL_REDIRECT_URI` — full callback URL, e.g. `https://myapp.com/zitadel/callback`
   - `ZITADEL_COOKIE_SECRET` — 64-char hex string; generate with `bin2hex(random_bytes(32))`
3. Follow your framework guide (links above)

## Security Model

- All session state is stored in two encrypted, HttpOnly, SameSite=Lax cookies:
  - `__nextgen_auth` — JWT access token (TTL from token `exp`)
  - `__nextgen_pkce` — PKCE state (TTL 600s, single-use)
- No server-side sessions. No database required.
- PKCE state is encrypted with XChaCha20-Poly1305 via `ext-sodium`.
- JWT validation uses `ext-openssl` with JWKS key fetching — no external packages.
