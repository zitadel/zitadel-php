Phalcon
=======

The Phalcon bridge supports two integration modes:

- **Micro** — :php:class:`Zitadel\Sdk\Bridge\Phalcon\ZitadelMicroPlugin` registers
  via ``$app->before()``, which fires before route matching.
- **MVC** — :php:class:`Zitadel\Sdk\Bridge\Phalcon\ZitadelPlugin` attaches to the
  ``application:beforeHandleRequest`` and ``dispatch:beforeDispatch`` events.

Both modes intercept the callback and logout paths without requiring routes in your
application.

.. note::

   Requires ``phalcon/phalcon ^6.0``. The bridge uses Phalcon 6 APIs directly
   (``$_COOKIE`` for cookie reads, ``header()`` with ``replace=false`` for
   cookie writes) and is **not compatible** with Phalcon 5.


Installation
------------

.. code-block:: bash

   composer require zitadel/sdk


Environment Variables
---------------------

.. code-block:: ini

   ZITADEL_ISSUER_URL=https://my.zitadel.cloud
   ZITADEL_CLIENT_ID=your-client-id
   ZITADEL_REDIRECT_URI=https://myapp.com/zitadel/callback
   ZITADEL_COOKIE_SECRET=

Generate a secure cookie secret (64 hex characters):

.. code-block:: bash

   php -r "echo bin2hex(random_bytes(32)) . PHP_EOL;"

.. note::

   Phalcon does not ship a console component, so there is no ``zitadel:generate-secret``
   command. Use the one-liner above or generate it in any other framework and copy the
   value.


Micro Application
-----------------

:php:class:`Zitadel\Sdk\Bridge\Phalcon\ZitadelMicroPlugin` implements Phalcon's
``MiddlewareInterface`` and registers via ``$app->before()``, which fires before
route matching. Callback and logout paths are intercepted without needing explicit
routes.

``public/index.php``:

.. code-block:: php

   use Phalcon\Mvc\Micro;
   use Zitadel\Sdk\Auth\JwksCache;
   use Zitadel\Sdk\Auth\TokenValidator;
   use Zitadel\Sdk\Bridge\Phalcon\ZitadelMicroPlugin;
   use Zitadel\Sdk\Config\ZitadelConfig;

   $config = new ZitadelConfig(
       issuerUrl:     $_ENV['ZITADEL_ISSUER_URL'],
       clientId:      $_ENV['ZITADEL_CLIENT_ID'],
       redirectUri:   $_ENV['ZITADEL_REDIRECT_URI'],
       cookieSecret:  $_ENV['ZITADEL_COOKIE_SECRET'],
       protectAll:    true,
       ignoredRoutes: ['/health'],
   );

   $app = new Micro();
   $app->before(new ZitadelMicroPlugin($config, new TokenValidator($config, new JwksCache())));

   $app->get('/dashboard', function () use ($app) {
       /** @var \Zitadel\Sdk\Auth\Claims|null $claims */
       $claims = $app->getDI()->get('zitadel.claims');
       echo json_encode(['name' => $claims?->name, 'sub' => $claims?->sub]);
   });

   $app->handle($_SERVER['REQUEST_URI']);

Claims are stored in the DI container under the key ``'zitadel.claims'`` after
successful token validation.

.. note::

   :php:class:`Zitadel\Sdk\Attribute\AllowAnonymous` is **not supported** in Micro
   applications. Phalcon Micro routes are typically closures, and PHP attributes cannot
   be applied to closures. Use ``ignoredRoutes`` to exempt specific paths.


MVC Application
---------------

:php:class:`Zitadel\Sdk\Bridge\Phalcon\ZitadelPlugin` listens on two events:

- ``application:beforeHandleRequest`` — fires before controller dispatch; handles the
  callback, logout, and PKCE redirect.
- ``dispatch:beforeDispatch`` — fires after the dispatcher resolves the controller and
  action; checks for ``#[AllowAnonymous]``.

Service Registration
~~~~~~~~~~~~~~~~~~~~

Register Zitadel via the static service provider in ``app/config/services.php``.
``ZitadelConfig::fromArray()`` accepts a plain PHP array with snake_case keys,
avoiding the need to name every constructor argument:

.. code-block:: php

   use Phalcon\Di\DiInterface;
   use Zitadel\Sdk\Bridge\Phalcon\ZitadelServiceProvider;
   use Zitadel\Sdk\Config\ZitadelConfig;

   ZitadelServiceProvider::create($di, ZitadelConfig::fromArray([
       'issuer_url'          => $config['zitadel']['issuerUrl'],
       'client_id'           => $config['zitadel']['clientId'],
       'redirect_uri'        => rtrim($config['app']['serverUrl'], '/') . '/zitadel/callback',
       'cookie_secret'       => $config['zitadel']['cookieSecret'],
       'post_login_redirect' => $config['zitadel']['postLoginUrl'],
       'post_logout_redirect'=> $config['zitadel']['postLogoutUrl'],
       'protect_all'         => true,
   ]));

:php:class:`Zitadel\Sdk\Bridge\Phalcon\ZitadelServiceProvider` implements
``Phalcon\Di\ServiceProviderInterface`` and can be used in two ways:

.. code-block:: php

   // Option A — standard DI provider pattern
   $di->register(new ZitadelServiceProvider($config));

   // Option B — static convenience alias (equivalent)
   ZitadelServiceProvider::create($di, $config);

Both register ``zitadelConfig``, ``zitadelValidator``, and ``zitadelPlugin`` in the DI
container and attach the plugin to both the ``application`` and ``dispatch`` event managers.

Entry Point
~~~~~~~~~~~

``public/index.php`` must handle the ``false`` return value from ``handle()``.
``ZitadelPlugin`` calls ``$response->send()`` and returns ``false`` when it
short-circuits (callback, logout, or protected-route redirect). The guard prevents
double output:

.. code-block:: php

   $application = new \Phalcon\Mvc\Application($di);
   $result      = $application->handle($_SERVER['REQUEST_URI']);

   if ($result !== false) {
       echo $result->getContent();
   }

Accessing Claims
~~~~~~~~~~~~~~~~

:php:class:`Zitadel\Sdk\Auth\Claims` are stored in the DI container under the key
``'zitadel.claims'`` after successful token validation:

.. code-block:: php

   use Phalcon\Mvc\Controller;
   use Zitadel\Sdk\Auth\Claims;

   class DashboardController extends Controller
   {
       public function indexAction(): string
       {
           /** @var Claims|null $claims */
           $claims = $this->di->get('zitadel.claims');

           return json_encode([
               'name'  => $claims?->name,
               'email' => $claims?->email,
               'sub'   => $claims?->sub,
           ]);
       }
   }


Protecting Routes
-----------------

Protect all routes (recommended)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Set ``protectAll`` to ``true`` and list public paths in ``ignoredRoutes``. This
applies to both Micro and MVC modes:

.. code-block:: php

   new ZitadelConfig(
       // ...
       protectAll:    true,
       ignoredRoutes: ['/health', '/public/*'],
   );

Protect specific routes
~~~~~~~~~~~~~~~~~~~~~~~

Leave ``protectAll`` unset (defaults to ``false``) and enumerate paths in
``protectedRoutes``:

.. code-block:: php

   new ZitadelConfig(
       // ...
       protectedRoutes: ['/dashboard*', '/admin*'],
   );


Opting Out
----------

Per-path (configuration)
~~~~~~~~~~~~~~~~~~~~~~~~

Add paths to ``ignoredRoutes`` when constructing
:php:class:`Zitadel\Sdk\Config\ZitadelConfig`:

.. code-block:: php

   new ZitadelConfig(
       // ...
       ignoredRoutes: ['/health', '/public/*'],
   );

Per-controller or per-method (MVC only)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

:php:class:`Zitadel\Sdk\Attribute\AllowAnonymous` is supported in MVC mode. The
``dispatch:beforeDispatch`` event fires after the dispatcher resolves the controller
name and action method, so the plugin can reflect on them:

.. code-block:: php

   use Phalcon\Mvc\Controller;
   use Zitadel\Sdk\Attribute\AllowAnonymous;

   // Entire controller is public
   #[AllowAnonymous]
   class HealthController extends Controller
   {
       public function indexAction(): string
       {
           return 'OK';
       }
   }

   // One action is public, the rest are protected
   class AccountController extends Controller
   {
       #[AllowAnonymous]
       public function loginAction(): \Phalcon\Http\ResponseInterface { ... }

       public function profileAction(): string { ... }
   }

.. note::

   :php:class:`Zitadel\Sdk\Attribute\AllowAnonymous` is **not supported** in Micro
   mode. Use ``ignoredRoutes`` instead.


Login / Logout Events
---------------------

Both :php:class:`Zitadel\Sdk\Bridge\Phalcon\ZitadelPlugin` (MVC) and
:php:class:`Zitadel\Sdk\Bridge\Phalcon\ZitadelMicroPlugin` (Micro) fire Phalcon events
through the application's events manager:

- ``zitadel:afterLogin`` — fired after successful PKCE callback, carries a
  :php:class:`Zitadel\Sdk\Event\ZitadelLoginEvent` as the third argument.
- ``zitadel:afterLogout`` — fired on the logout path, carries a
  :php:class:`Zitadel\Sdk\Event\ZitadelLogoutEvent` as the third argument.

Attach listeners to the same ``EventsManager`` that the plugin is registered on:

.. code-block:: php

   use Phalcon\Events\Event;
   use Zitadel\Sdk\Event\ZitadelLoginEvent;
   use Zitadel\Sdk\Event\ZitadelLogoutEvent;

   $eventsManager->attach(
       'zitadel:afterLogin',
       function (Event $event, mixed $source, ZitadelLoginEvent $loginEvent): void {
           $claims = $loginEvent->claims;
           // Sync user record, update last_seen, write audit log, etc.
       }
   );

   $eventsManager->attach(
       'zitadel:afterLogout',
       function (Event $event, mixed $source, ZitadelLogoutEvent $logoutEvent): void {
           // Clean up, audit log, etc.
       }
   );


Forwarding Tokens
-----------------

:php:attr:`Zitadel\Sdk\Auth\Claims::$token` contains the raw signed JWT. Forward it as
a ``Bearer`` token to any downstream service that validates JWTs independently:

.. code-block:: php

   use Phalcon\Mvc\Controller;
   use Zitadel\Sdk\Auth\Claims;

   class OrdersController extends Controller
   {
       public function indexAction(): string
       {
           /** @var Claims|null $claims */
           $claims = $this->di->get('zitadel.claims');

           $client   = new \GuzzleHttp\Client();
           $response = $client->get('https://api.internal/v1/orders', [
               'headers' => ['Authorization' => 'Bearer ' . $claims?->token],
           ]);

           return $response->getBody()->getContents();
       }
   }
