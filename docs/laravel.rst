Laravel
=======

The Laravel bridge auto-discovers via Composer's ``extra.laravel.providers`` entry,
registers a custom Auth guard, and exposes the authenticated user through the standard
``auth()->user()`` API. No routes and no manual service registration are required —
install, configure, and go.

.. note::

   Supports Laravel 10 and 11.


Installation
------------

.. code-block:: bash

   composer require zitadel/sdk

:php:class:`Zitadel\Sdk\Bridge\Laravel\ZitadelServiceProvider` is auto-discovered by
Laravel. No entry is needed in ``config/app.php``.


Environment Variables
---------------------

Add to your ``.env`` file:

.. code-block:: ini

   ZITADEL_ISSUER_URL=https://my.zitadel.cloud
   ZITADEL_CLIENT_ID=your-client-id
   ZITADEL_REDIRECT_URI=https://myapp.com/zitadel/callback
   ZITADEL_COOKIE_SECRET=

Generate a secure cookie secret (64 hex characters):

.. code-block:: bash

   php -r "echo bin2hex(random_bytes(32)) . PHP_EOL;"


Configuration
-------------

Publish the config file to customise options beyond the four required environment
variables:

.. code-block:: bash

   php artisan vendor:publish --tag=zitadel-config

This creates ``config/zitadel.php`` in your application. The four required values are
read from environment variables by default, so publishing is only necessary when you
need to change optional settings such as ``protect_all``, ``ignored_routes``, or
``scopes``.


Protecting Routes
-----------------

Protect all routes (recommended)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Set ``protect_all`` to ``true`` and list public paths in ``ignored_routes``. Every
route requires a valid session unless explicitly exempted — the most secure default for
applications where most pages require authentication.

.. code-block:: php

   // config/zitadel.php
   return [
       'protect_all'    => true,
       'ignored_routes' => ['/health', '/'],
   ];

Protect specific routes
~~~~~~~~~~~~~~~~~~~~~~~

Use ``protected_routes`` with ``prefix*`` wildcards to opt individual paths in:

.. code-block:: php

   return [
       'protect_all'      => false,
       'protected_routes' => ['/dashboard*', '/admin*', '/api/v1*'],
   ];


Accessing Claims
----------------

:php:class:`Zitadel\Sdk\Bridge\Laravel\ZitadelServiceProvider` registers a ``zitadel``
Auth guard backed by :php:class:`Zitadel\Sdk\Bridge\Laravel\Auth\ZitadelGuard`. After
:php:class:`Zitadel\Sdk\Bridge\Laravel\Http\Middleware\ZitadelMiddleware` validates the
session, the guard resolves to a
:php:class:`Zitadel\Sdk\Bridge\Laravel\Auth\ZitadelUser` wrapping the
:php:class:`Zitadel\Sdk\Auth\Claims` object.

.. code-block:: php

   use Zitadel\Sdk\Bridge\Laravel\Auth\ZitadelUser;

   class DashboardController extends Controller
   {
       public function __invoke(): Response
       {
           /** @var ZitadelUser $user */
           $user = auth('zitadel')->user();

           return view('dashboard', [
               'name'  => $user->claims->name,
               'email' => $user->claims->email,
               'sub'   => $user->claims->sub,
           ]);
       }
   }

To use the shorter ``auth()->user()`` form, set ``zitadel`` as the default guard in
``config/auth.php``:

.. code-block:: php

   'defaults' => ['guard' => 'zitadel'],
   'guards'   => ['zitadel' => ['driver' => 'zitadel']],

You can also read :php:class:`Zitadel\Sdk\Auth\Claims` directly from the request
attributes, which is useful in middleware or non-controller code:

.. code-block:: php

   /** @var \Zitadel\Sdk\Auth\Claims|null $claims */
   $claims = $request->attributes->get('zitadel.claims');


Opting Out
----------

Per-route (native Laravel)
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Use Laravel's built-in ``withoutMiddleware()`` on any route definition:

.. code-block:: php

   use Zitadel\Sdk\Bridge\Laravel\Http\Middleware\ZitadelMiddleware;

   Route::get('/public', PublicController::class)
       ->withoutMiddleware(ZitadelMiddleware::class);

Per-controller or per-method
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

:php:class:`Zitadel\Sdk\Attribute\AllowAnonymous` marks a controller class or action
method as publicly accessible. Unauthenticated requests are allowed through;
``zitadel.claims`` is ``null`` in the handler.

.. code-block:: php

   use Zitadel\Sdk\Attribute\AllowAnonymous;

   // Entire controller is public
   #[AllowAnonymous]
   class MarketingController extends Controller
   {
       public function landing(): Response { ... }
       public function pricing(): Response { ... }
   }

   // One action is public, the rest are protected
   class AccountController extends Controller
   {
       #[AllowAnonymous]
       public function login(): Response { ... }

       public function profile(): Response { ... }
   }

.. note::

   ``#[AllowAnonymous]`` requires ``ZitadelMiddleware`` to run in the ``web``
   middleware group (the default). Route resolution must occur before the middleware
   can reflect on the controller class and method.


Forwarding Tokens
-----------------

:php:attr:`Zitadel\Sdk\Auth\Claims::$token` contains the raw signed JWT. Forward it as
a ``Bearer`` token to any downstream service that validates JWTs independently:

.. code-block:: php

   use Illuminate\Support\Facades\Http;

   $user     = auth('zitadel')->user();
   $response = Http::withHeaders([
       'Authorization' => 'Bearer ' . $user->claims->token,
   ])->get('https://api.internal/v1/orders');


Using ``auth:zitadel`` Route Middleware
----------------------------------------

The ``auth:zitadel`` route middleware is Laravel's built-in ``Authenticate`` middleware
backed by :php:class:`Zitadel\Sdk\Bridge\Laravel\Auth\ZitadelGuard`. For web (cookie)
flows, declaring protected routes via ``ZitadelConfig`` is the recommended approach —
unauthenticated users are redirected to Zitadel before route-specific middleware fires.

Use ``auth:zitadel`` for **API routes** where clients send Bearer tokens directly and
manage the PKCE flow independently:

.. code-block:: php

   Route::middleware('auth:zitadel')->group(function () {
       Route::get('/api/profile', ProfileController::class);
   });


Testing
-------

Laravel's ``actingAs()`` works normally with the ``zitadel`` guard.
:php:class:`Zitadel\Sdk\Bridge\Laravel\Auth\ZitadelGuard` implements the standard
``Guard`` contract and is not ``final``, so ``Auth::fake()`` and ``actingAs()`` work
without any special setup:

.. code-block:: php

   use Zitadel\Sdk\Auth\Claims;
   use Zitadel\Sdk\Bridge\Laravel\Auth\ZitadelUser;

   $claims = new Claims(
       sub:   'user-123',
       iss:   'https://my.zitadel.cloud',
       exp:   time() + 3600,
       token: 'fake-token',
       name:  'Alice Example',
       email: 'alice@example.com',
   );

   $this->actingAs(new ZitadelUser($claims), 'zitadel');

   $this->get('/dashboard')->assertStatus(200);
