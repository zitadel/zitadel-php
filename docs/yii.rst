Yii 3
=====

Yii 3 is PSR-15 native. The core
:php:class:`Zitadel\Sdk\Middleware\ZitadelMiddleware` slots directly into the
middleware pipeline — no adapter is required. The thin
:php:class:`Zitadel\Sdk\Bridge\Yii\ZitadelBootstrap` helper wires the DI bindings.

.. note::

   Requires ``yiisoft/yii-web ^3.0`` and a PSR-7 factory such as ``nyholm/psr7``.


Installation
------------

.. code-block:: bash

   composer require zitadel/zitadel-php nyholm/psr7


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

Bind the middleware and its dependencies in ``config/web/di.php``:

.. code-block:: php

   use Nyholm\Psr7\Factory\Psr17Factory;
   use Psr\Http\Message\ResponseFactoryInterface;
   use Zitadel\Sdk\Auth\JwksCache;
   use Zitadel\Sdk\Auth\TokenValidator;
   use Zitadel\Sdk\Config\ZitadelConfig;
   use Zitadel\Sdk\Middleware\ZitadelMiddleware;

   return [
       ResponseFactoryInterface::class => Psr17Factory::class,

       ZitadelConfig::class => [
           '__class'       => ZitadelConfig::class,
           '__construct()' => [
               'issuerUrl'     => $_ENV['ZITADEL_ISSUER_URL'],
               'clientId'      => $_ENV['ZITADEL_CLIENT_ID'],
               'redirectUri'   => $_ENV['ZITADEL_REDIRECT_URI'],
               'cookieSecret'  => $_ENV['ZITADEL_COOKIE_SECRET'],
               'protectAll'    => true,
               'ignoredRoutes' => ['/health'],
           ],
       ],

       JwksCache::class         => ['__class' => JwksCache::class],
       TokenValidator::class    => ['__class' => TokenValidator::class],
       ZitadelMiddleware::class => ['__class' => ZitadelMiddleware::class],
   ];


Protecting Routes
-----------------

Protect all routes (recommended)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Set ``protectAll`` to ``true`` and list public paths in ``ignoredRoutes``:

.. code-block:: php

   '__construct()' => [
       // ...
       'protectAll'    => true,
       'ignoredRoutes' => ['/health', '/api/public/*'],
   ],

Protect specific routes
~~~~~~~~~~~~~~~~~~~~~~~

Leave ``protectAll`` unset (defaults to ``false``) and enumerate paths in
``protectedRoutes``:

.. code-block:: php

   '__construct()' => [
       // ...
       'protectedRoutes' => ['/dashboard*', '/admin*'],
   ],


Pipeline Position
-----------------

The position of ``ZitadelMiddleware`` in the pipeline determines which features are
available.

Before routing (recommended)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Place ``ZitadelMiddleware`` **before** ``Router::class`` in
``config/web/application.php``. The middleware intercepts the callback and logout
paths before routing runs. ``#[AllowAnonymous]`` reflection is not available because
the route has not been resolved yet.

.. code-block:: php

   use Yiisoft\Router\Middleware\Router;
   use Zitadel\Sdk\Middleware\ZitadelMiddleware;

   return [
       'middlewares' => [
           ZitadelMiddleware::class,
           Router::class,
       ],
   ];

After routing (``#[AllowAnonymous]`` support)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Place ``ZitadelMiddleware`` **after** ``Router::class``. The middleware can then
reflect on the matched route handler for ``#[AllowAnonymous]``. In this configuration
you must add explicit routes for the callback and logout paths.

.. code-block:: php

   return [
       'middlewares' => [
           Router::class,
           ZitadelMiddleware::class,
       ],
   ];

.. tip::

   Use before-routing placement for most applications and exempt public paths via
   ``ignoredRoutes``. Switch to after-routing placement only when you need
   per-action ``#[AllowAnonymous]`` granularity.


Accessing Claims
----------------

:php:class:`Zitadel\Sdk\Auth\Claims` are attached to the PSR-7 request under the
attribute key ``"zitadel.claims"``:

.. code-block:: php

   use Psr\Http\Message\ResponseInterface;
   use Psr\Http\Message\ServerRequestInterface;
   use Zitadel\Sdk\Auth\Claims;

   class DashboardAction
   {
       public function __invoke(
           ServerRequestInterface $request,
           ResponseInterface      $response,
       ): ResponseInterface {
           /** @var Claims|null $claims */
           $claims = $request->getAttribute('zitadel.claims');

           $response->getBody()->write(
               json_encode(['name' => $claims?->name, 'sub' => $claims?->sub])
           );
           return $response->withHeader('Content-Type', 'application/json');
       }
   }


Opting Out
----------

Per-path (configuration)
~~~~~~~~~~~~~~~~~~~~~~~~

Add paths to ``ignoredRoutes`` in the DI container configuration:

.. code-block:: php

   'ignoredRoutes' => ['/health', '/public/*'],

Per-controller or per-method
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When the middleware runs **after** the router, it reflects on the matched route handler
for :php:class:`Zitadel\Sdk\Attribute\AllowAnonymous`:

.. code-block:: php

   use Zitadel\Sdk\Attribute\AllowAnonymous;

   class HealthAction
   {
       #[AllowAnonymous]
       public function __invoke(
           ServerRequestInterface $request,
           ResponseInterface      $response,
       ): ResponseInterface {
           $response->getBody()->write('OK');
           return $response;
       }
   }


Forwarding Tokens
-----------------

:php:attr:`Zitadel\Sdk\Auth\Claims::$token` contains the raw signed JWT. Forward it as
a ``Bearer`` token to any downstream service that validates JWTs independently:

.. code-block:: php

   /** @var Claims|null $claims */
   $claims = $request->getAttribute('zitadel.claims');

   $downstream = $httpClient->request(
       'GET',
       'https://api.internal/v1/profile',
       ['headers' => ['Authorization' => 'Bearer ' . $claims?->token]],
   );
