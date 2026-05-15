Yii 3
=====

The Yii 3 bridge provides a dedicated PSR-15 middleware that integrates with
``yiisoft/router`` to support ``#[AllowAnonymous]`` attribute detection. Unlike the
generic :php:class:`Zitadel\Sdk\Middleware\ZitadelMiddleware`, the bridge pre-resolves
the matched route using ``UrlMatcherInterface`` and reflects on the action class before
the router dispatches the request.

.. note::

   Requires ``yiisoft/router ^3.0``, ``yiisoft/router-fastroute ^3.0``, and a PSR-7
   factory such as ``nyholm/psr7``.


Installation
------------

.. code-block:: bash

   composer require zitadel/sdk yiisoft/router yiisoft/router-fastroute nyholm/psr7


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

Bind the bridge middleware and its dependencies in ``config/web/di.php``:

.. code-block:: php

   use Nyholm\Psr7\Factory\Psr17Factory;
   use Psr\Http\Message\ResponseFactoryInterface;
   use Yiisoft\Router\FastRoute\UrlMatcher;
   use Yiisoft\Router\RouteCollection;
   use Yiisoft\Router\RouteCollectionInterface;
   use Yiisoft\Router\RouteCollector;
   use Yiisoft\Router\UrlMatcherInterface;
   use Zitadel\Sdk\Auth\JwksCache;
   use Zitadel\Sdk\Auth\JwksCacheInterface;
   use Zitadel\Sdk\Auth\TokenValidator;
   use Zitadel\Sdk\Bridge\Yii\ZitadelMiddleware;
   use Zitadel\Sdk\Config\ZitadelConfig;

   $appConfig = require __DIR__ . '/application.php';

   return [
       ResponseFactoryInterface::class => Psr17Factory::class,

       ZitadelConfig::class => [
           'class'         => ZitadelConfig::class,
           '__construct()' => [
               'issuerUrl'     => $_ENV['ZITADEL_ISSUER_URL'],
               'clientId'      => $_ENV['ZITADEL_CLIENT_ID'],
               'redirectUri'   => $_ENV['ZITADEL_REDIRECT_URI'],
               'cookieSecret'  => $_ENV['ZITADEL_COOKIE_SECRET'],
               'protectAll'    => true,
               'ignoredRoutes' => ['/health'],
           ],
       ],

       JwksCacheInterface::class => JwksCache::class,
       JwksCache::class          => JwksCache::class,
       TokenValidator::class     => TokenValidator::class,

       RouteCollectionInterface::class => static function () use ($appConfig): RouteCollectionInterface {
           $collector = new RouteCollector();
           $collector->addRoute(...$appConfig['routes']);
           return new RouteCollection($collector);
       },

       UrlMatcherInterface::class => UrlMatcher::class,
       ZitadelMiddleware::class   => ZitadelMiddleware::class,
   ];

Register routes and declare the middleware pipeline in ``config/web/application.php``:

.. code-block:: php

   use App\Action\DashboardAction;
   use App\Action\HomeAction;
   use Yiisoft\Router\Middleware\Router;
   use Yiisoft\Router\Route;
   use Zitadel\Sdk\Bridge\Yii\ZitadelMiddleware;

   return [
       'middlewares' => [
           ZitadelMiddleware::class,
           Router::class,
       ],

       'routes' => [
           Route::get('/dashboard')->action(DashboardAction::class)->name('dashboard'),
           Route::get('/home')->action(HomeAction::class)->name('home'),
       ],
   ];

The bridge must be **before** ``Router::class`` so it can intercept the callback and
logout paths before routing runs. ``#[AllowAnonymous]`` reflection still works because
the bridge pre-resolves the route internally using ``UrlMatcherInterface::match()``.


Protecting Routes
-----------------

Protect all routes (recommended)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Set ``protectAll`` to ``true`` and list public infrastructure paths in
``ignoredRoutes``:

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

Add paths to ``ignoredRoutes`` in the DI container configuration. Use this for
infrastructure endpoints that need no authentication context whatsoever:

.. code-block:: php

   'ignoredRoutes' => ['/health', '/public/*'],

Per-action
~~~~~~~~~~

Apply :php:class:`Zitadel\Sdk\Attribute\AllowAnonymous` to the action class or its
``__invoke`` method. The bridge reflects on the matched action before deciding whether
to redirect unauthenticated requests. A valid Bearer token is still extracted and
validated when present, so the action can serve different responses to authenticated
and anonymous callers:

.. code-block:: php

   use Zitadel\Sdk\Attribute\AllowAnonymous;
   use Zitadel\Sdk\Auth\Claims;

   #[AllowAnonymous]
   class ApiAction
   {
       public function __invoke(
           ServerRequestInterface $request,
           ResponseInterface      $response,
       ): ResponseInterface {
           /** @var Claims|null $claims */
           $claims  = $request->getAttribute('zitadel.claims');
           $payload = $claims !== null
               ? ['authenticated' => true,  'sub' => $claims->sub]
               : ['authenticated' => false];

           $response->getBody()->write(json_encode($payload));
           return $response->withHeader('Content-Type', 'application/json');
       }
   }

.. note::

   ``ignoredRoutes`` bypasses the middleware entirely — no token extraction, no claims.
   ``#[AllowAnonymous]`` runs inside the middleware, so a valid Bearer token still
   populates ``zitadel.claims`` when present. Choose ``ignoredRoutes`` for health
   checks and ``#[AllowAnonymous]`` for mixed-auth application routes.


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
