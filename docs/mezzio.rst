Mezzio (Laminas)
================

Mezzio is PSR-15 native. The core
:php:class:`Zitadel\Sdk\Middleware\ZitadelMiddleware` is piped with ``$app->pipe()``
directly — no adapter, no bridge class. The position of the middleware in the pipeline
determines which features are available.

.. note::

   Requires ``mezzio/mezzio ^3.0`` (Laminas Mezzio) and a PSR-7 factory.


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

DI Container
~~~~~~~~~~~~

Register the middleware and its dependencies in
``config/autoload/zitadel.global.php``:

.. code-block:: php

   use Nyholm\Psr7\Factory\Psr17Factory;
   use Psr\Http\Message\ResponseFactoryInterface;
   use Zitadel\Sdk\Auth\JwksCache;
   use Zitadel\Sdk\Auth\JwksCacheInterface;
   use Zitadel\Sdk\Auth\TokenValidator;
   use Zitadel\Sdk\Config\ZitadelConfig;
   use Zitadel\Sdk\Middleware\ZitadelMiddleware;

   return [
       'dependencies' => [
           'factories' => [
               ZitadelConfig::class     => fn($c) => new ZitadelConfig(
                   issuerUrl:     $_ENV['ZITADEL_ISSUER_URL'],
                   clientId:      $_ENV['ZITADEL_CLIENT_ID'],
                   redirectUri:   $_ENV['ZITADEL_REDIRECT_URI'],
                   cookieSecret:  $_ENV['ZITADEL_COOKIE_SECRET'],
                   protectAll:    true,
                   ignoredRoutes: ['/health'],
               ),
               TokenValidator::class    => fn($c) => new TokenValidator(
                   $c->get(ZitadelConfig::class),
                   $c->get(JwksCacheInterface::class),
               ),
               ZitadelMiddleware::class => fn($c) => new ZitadelMiddleware(
                   $c->get(ZitadelConfig::class),
                   $c->get(TokenValidator::class),
                   $c->get(ResponseFactoryInterface::class),
               ),
           ],
           'aliases' => [
               ResponseFactoryInterface::class => Psr17Factory::class,
               JwksCacheInterface::class       => JwksCache::class,
           ],
           'invokables' => [
               JwksCache::class    => JwksCache::class,
               Psr17Factory::class => Psr17Factory::class,
           ],
       ],
   ];

Pipeline
~~~~~~~~

The position in the pipeline determines which features are available.

**Before routing (recommended)**: ``ZitadelMiddleware`` runs before ``RouteMiddleware``.
Callback and logout paths are intercepted without needing explicit routes.
``#[AllowAnonymous]`` reflection is not available because the route has not been
resolved yet.

``config/pipeline.php``:

.. code-block:: php

   use Mezzio\Router\Middleware\RouteMiddleware;
   use Mezzio\Router\Middleware\DispatchMiddleware;
   use Zitadel\Sdk\Middleware\ZitadelMiddleware;

   $app->pipe(ZitadelMiddleware::class);
   $app->pipe(RouteMiddleware::class);
   $app->pipe(DispatchMiddleware::class);

**After routing (``#[AllowAnonymous]`` support)**: Place ``ZitadelMiddleware`` after
``RouteMiddleware``. The middleware reads the ``RouteResult`` attribute to reflect on
the matched handler. You must add explicit routes for the callback and logout paths in
this configuration.

.. code-block:: php

   $app->pipe(RouteMiddleware::class);
   $app->pipe(ZitadelMiddleware::class);
   $app->pipe(DispatchMiddleware::class);

.. tip::

   Use before-routing placement for most applications. Switch to after-routing only
   when you need ``#[AllowAnonymous]`` on individual handler methods.


Protecting Routes
-----------------

Protect all routes (recommended)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Set ``protectAll`` to ``true`` and list public paths in ``ignoredRoutes``:

.. code-block:: php

   new ZitadelConfig(
       // ...
       protectAll:    true,
       ignoredRoutes: ['/health', '/api/public/*'],
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


Accessing Claims
----------------

:php:class:`Zitadel\Sdk\Auth\Claims` are attached to the PSR-7 request under the
attribute key ``"zitadel.claims"``:

.. code-block:: php

   use Psr\Http\Message\ResponseInterface;
   use Psr\Http\Message\ServerRequestInterface;
   use Psr\Http\Server\RequestHandlerInterface;
   use Zitadel\Sdk\Auth\Claims;

   class DashboardHandler implements RequestHandlerInterface
   {
       public function handle(ServerRequestInterface $request): ResponseInterface
       {
           /** @var Claims|null $claims */
           $claims = $request->getAttribute('zitadel.claims');

           return new JsonResponse([
               'name'  => $claims?->name,
               'email' => $claims?->email,
               'sub'   => $claims?->sub,
           ]);
       }
   }


Opting Out
----------

Per-path (configuration)
~~~~~~~~~~~~~~~~~~~~~~~~

Add paths to ``ignoredRoutes`` when constructing
:php:class:`Zitadel\Sdk\Config\ZitadelConfig`:

.. code-block:: php

   new ZitadelConfig(
       // ...
       ignoredRoutes: ['/health', '/api/public/*'],
   );

Per-handler (``#[AllowAnonymous]``)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When the middleware runs after ``RouteMiddleware``, it reflects on the matched handler
for :php:class:`Zitadel\Sdk\Attribute\AllowAnonymous`:

.. code-block:: php

   use Psr\Http\Message\ResponseInterface;
   use Psr\Http\Message\ServerRequestInterface;
   use Psr\Http\Server\RequestHandlerInterface;
   use Zitadel\Sdk\Attribute\AllowAnonymous;

   class HealthHandler implements RequestHandlerInterface
   {
       #[AllowAnonymous]
       public function handle(ServerRequestInterface $request): ResponseInterface
       {
           return new TextResponse('OK');
       }
   }


Forwarding Tokens
-----------------

:php:attr:`Zitadel\Sdk\Auth\Claims::$token` contains the raw signed JWT. Forward it as
a ``Bearer`` token to any downstream service that validates JWTs independently:

.. code-block:: php

   use Zitadel\Sdk\Auth\Claims;

   class OrdersHandler implements RequestHandlerInterface
   {
       public function __construct(
           private readonly ClientInterface $httpClient,
       ) {}

       public function handle(ServerRequestInterface $request): ResponseInterface
       {
           /** @var Claims|null $claims */
           $claims = $request->getAttribute('zitadel.claims');

           $response = $this->httpClient->sendRequest(
               new Request('GET', 'https://api.internal/v1/orders', [
                   'Authorization' => 'Bearer ' . $claims?->token,
               ])
           );

           return new JsonResponse(
               json_decode($response->getBody()->getContents(), true)
           );
       }
   }
