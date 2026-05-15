Zitadel PHP SDK
===============

Zero-dependency PKCE authentication middleware for PHP 8.3+. Handles the full
OAuth 2.0 Authorization Code + PKCE flow, validates JWTs via JWKS, and stores all
session state in encrypted HttpOnly cookies — no server-side sessions, no database,
no custom routes required in your application.

.. code-block:: bash

   composer require zitadel/sdk


How It Works
------------

Every request passes through :php:class:`Zitadel\Sdk\Middleware\ZitadelMiddleware`
(PSR-15) or a thin framework bridge. The middleware owns the complete lifecycle:

1. **Callback** — Validates PKCE state, exchanges the authorization code for tokens,
   validates the access token, and sets the ``__nextgen_auth`` session cookie.
2. **Logout** — Deletes the session cookie and redirects to Zitadel's end-session endpoint.
3. **Protected route, no session** — Generates a PKCE challenge, saves state in the
   ``__nextgen_pkce`` cookie, and redirects to Zitadel's authorization endpoint.
4. **Protected route, valid session** — Validates the JWT from the cookie (or
   ``Authorization: Bearer`` header), attaches a :php:class:`Zitadel\Sdk\Auth\Claims`
   object to the request, and passes through to your controller.
5. **Public route** — Passes through; ``zitadel.claims`` is ``null``.

No routes need to be registered in your application. The middleware intercepts the
callback and logout paths before the framework router runs.


Framework Guides
----------------

.. toctree::
   :hidden:
   :maxdepth: 1

   laravel
   symfony
   yii
   slim
   mezzio
   codeigniter
   phalcon

+---------------------+----------------------------------------------------+--------------------------------------+
| Framework           | Integration style                                  | Claims access                        |
+=====================+====================================================+======================================+
| :doc:`laravel`      | Auto-discovered ServiceProvider, Auth guard        | ``auth('zitadel')->user()->claims``  |
+---------------------+----------------------------------------------------+--------------------------------------+
| :doc:`symfony`      | Bundle + KernelEvents listener                     | ``?Claims $claims`` (auto-resolved)  |
+---------------------+----------------------------------------------------+--------------------------------------+
| :doc:`yii`          | PSR-15 pipeline, no bridge                         | ``$request->getAttribute(...)``      |
+---------------------+----------------------------------------------------+--------------------------------------+
| :doc:`slim`         | PSR-15 native, no bridge                           | ``$request->getAttribute(...)``      |
+---------------------+----------------------------------------------------+--------------------------------------+
| :doc:`mezzio`       | PSR-15 native, no bridge                           | ``$request->getAttribute(...)``      |
+---------------------+----------------------------------------------------+--------------------------------------+
| :doc:`codeigniter`  | FilterInterface bridge                             | ``ZitadelHolder::claims()``          |
+---------------------+----------------------------------------------------+--------------------------------------+
| :doc:`phalcon`      | Micro MiddlewareInterface / MVC event plugin       | ``$this->di->get('zitadel.claims')`` |
+---------------------+----------------------------------------------------+--------------------------------------+


Quick Start
-----------

**1. Install**

.. code-block:: bash

   composer require zitadel/sdk

**2. Generate a cookie secret**

.. code-block:: bash

   php -r "echo bin2hex(random_bytes(32)) . PHP_EOL;"

**3. Set environment variables**

.. code-block:: ini

   ZITADEL_ISSUER_URL=https://my.zitadel.cloud
   ZITADEL_CLIENT_ID=your-client-id
   ZITADEL_REDIRECT_URI=https://myapp.com/zitadel/callback
   ZITADEL_COOKIE_SECRET=<64-char hex string from step 2>

**4. Follow your framework guide** (links above).


Configuration Reference
-----------------------

All options are constructor parameters of :php:class:`Zitadel\Sdk\Config\ZitadelConfig`.

.. list-table::
   :header-rows: 1
   :widths: 25 12 10 53

   * - Option
     - Type
     - Default
     - Description
   * - ``issuerUrl``
     - ``string``
     - —
     - Base URL of your Zitadel instance, e.g. ``https://my.zitadel.cloud``.
       Must use ``https://`` (``http://localhost`` is the only exception).
   * - ``clientId``
     - ``string``
     - —
     - OAuth 2.0 client ID registered in Zitadel.
   * - ``redirectUri``
     - ``string``
     - —
     - Full callback URL, e.g. ``https://myapp.com/zitadel/callback``.
       Must match the redirect URI configured in Zitadel exactly.
   * - ``cookieSecret``
     - ``string``
     - —
     - 64-character hex string (32 raw bytes). Used to encrypt the PKCE state
       cookie with XChaCha20-Poly1305. Generate with ``bin2hex(random_bytes(32))``.
   * - ``callbackPath``
     - ``string``
     - ``/zitadel/callback``
     - Path intercepted to handle the OAuth callback and token exchange.
   * - ``logoutPath``
     - ``string``
     - ``/zitadel/logout``
     - Path intercepted to clear the session and redirect to Zitadel's
       end-session endpoint.
   * - ``postLoginRedirect``
     - ``string``
     - ``/``
     - Where to redirect after successful login. Overridden by the originally
       requested path stored in the PKCE state cookie when available.
   * - ``postLogoutRedirect``
     - ``string``
     - ``/``
     - Where to redirect after logout. Sent as ``post_logout_redirect_uri`` to
       Zitadel.
   * - ``protectAll``
     - ``bool``
     - ``false``
     - When ``true``, all routes require a valid session. Use ``ignoredRoutes``
       or ``#[AllowAnonymous]`` to exempt specific paths. Recommended default for
       most applications.
   * - ``protectedRoutes``
     - ``string[]``
     - ``[]``
     - Paths that require auth when ``protectAll`` is ``false``.
       Supports ``prefix*`` wildcards, e.g. ``['/dashboard*', '/admin*']``.
   * - ``ignoredRoutes``
     - ``string[]``
     - ``[]``
     - Paths skipped entirely — no token validation, no redirect. Takes
       precedence over ``protectAll``. Supports ``prefix*`` wildcards.
   * - ``scopes``
     - ``string[]``
     - ``['openid', 'profile', 'email']``
     - OAuth 2.0 scopes requested during authorization. Must include ``openid``.
   * - ``allowedAlgorithms``
     - ``Algorithm[]``
     - ``[RS256, ES256]``
     - JWT signing algorithms accepted during validation. See
       :php:class:`Zitadel\Sdk\Auth\Algorithm`.
   * - ``allowedTokenTypes``
     - ``TokenType[]``
     - ``[JWT, at+JWT]``
     - Accepted ``typ`` header values. See :php:class:`Zitadel\Sdk\Auth\TokenType`.
   * - ``audience``
     - ``string|array|null``
     - ``null``
     - Expected ``aud`` claim. ``null`` skips the audience check.
   * - ``clockSkewSeconds``
     - ``int``
     - ``5``
     - Tolerance for clock drift between servers (applied to ``exp``, ``nbf``, ``iat``).
   * - ``jwksTtlSeconds``
     - ``int``
     - ``300``
     - How long (seconds) fetched JWKS keys are cached in-process.
   * - ``httpTimeoutSeconds``
     - ``int``
     - ``5``
     - Timeout for JWKS fetches and token exchange HTTP calls.


Claims Reference
----------------

After successful token validation, a :php:class:`Zitadel\Sdk\Auth\Claims` instance
is attached to the request. All properties are ``readonly``.

.. list-table::
   :header-rows: 1
   :widths: 20 15 65

   * - Property
     - Type
     - Description
   * - ``$sub``
     - ``string``
     - Subject identifier — the Zitadel user ID. Always present.
   * - ``$iss``
     - ``string``
     - Issuer URL. Matches ``ZitadelConfig::$issuerUrl``.
   * - ``$exp``
     - ``int``
     - Token expiration timestamp (Unix epoch).
   * - ``$token``
     - ``string``
     - Raw signed JWT string. Forward this as ``Authorization: Bearer`` to
       downstream services that validate the token independently.
   * - ``$name``
     - ``string|null``
     - Full display name (OIDC ``name`` claim).
   * - ``$email``
     - ``string|null``
     - Email address (OIDC ``email`` claim).
   * - ``$givenName``
     - ``string|null``
     - Given name (OIDC ``given_name`` claim).
   * - ``$familyName``
     - ``string|null``
     - Family name (OIDC ``family_name`` claim).
   * - ``$payload``
     - ``array``
     - Full decoded JWT payload. Use this to access custom Zitadel metadata,
       roles, or any claim not exposed as a typed property.


Cookie Reference
----------------

The library uses two cookies. No other state is stored.

.. list-table::
   :header-rows: 1
   :widths: 25 15 60

   * - Cookie
     - TTL
     - Contents
   * - ``__nextgen_auth``
     - ``exp - now()`` seconds
     - JWT access token (raw). HttpOnly, SameSite=Lax, Secure on HTTPS.
   * - ``__nextgen_pkce``
     - 600 seconds
     - Encrypted PKCE state: verifier, CSRF state token, and the original
       request URI. HttpOnly, SameSite=Lax, Secure on HTTPS. Single-use —
       deleted immediately on callback.


Security Model
--------------

- ``alg: none`` is always rejected, unconditionally, before any JWKS fetch.
- JWT must have exactly three segments — JWE (five-segment) tokens are rejected.
- ``iss`` is validated with strict string equality against ``issuerUrl``.
- ``sub`` must be present; tokens without a subject are rejected.
- PKCE state is encrypted with **XChaCha20-Poly1305** via ``ext-sodium``.
- The PKCE cookie is deleted immediately on callback (single-use verifier).
- The CSRF state parameter is validated against the PKCE cookie before code exchange.
  A mismatch returns HTTP 400, not a redirect.
- The exchanged access token is validated with ``TokenValidator`` *before* the session
  cookie is set — an unvalidated token is never stored.
- ``cookieSecret`` is validated via ``hex2bin()`` to exactly 32 bytes at construction time.
- cURL SSL peer verification is always enabled.
- The ``Secure`` cookie flag is set only when the request arrived over HTTPS,
  using each framework's native ``isSecure()`` method (respects trusted proxies).
