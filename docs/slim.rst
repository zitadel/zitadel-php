Slim 4
======

Slim 4 is PSR-15 native. The core
:php:class:`Zitadel\Sdk\Middleware\ZitadelMiddleware` is added with ``$app->add()``
directly — no adapter, no bridge class. This is the most minimal integration in the
library: construct two objects, call one method.


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

Wire up the middleware in your bootstrap file (``public/index.php`` or similar):

.. code-block:: php

   use Nyholm\Psr7\Factory\Psr17Factory;
   use Psr\Http\Message\ResponseInterface as Response;
   use Psr\Http\Message\ServerRequestInterface as Request;
   use Slim\Factory\AppFactory;
   use Zitadel\Sdk\Auth\JwksCache;
   use Zitadel\Sdk\Auth\TokenValidator;
   use Zitadel\Sdk\Config\ZitadelConfig;
   use Zitadel\Sdk\Middleware\ZitadelMiddleware;

   $psr17 = new Psr17Factory();

   $config = new ZitadelConfig(
       issuerUrl:     $_ENV['ZITADEL_ISSUER_URL'],
       clientId:      $_ENV['ZITADEL_CLIENT_ID'],
       redirectUri:   $_ENV['ZITADEL_REDIRECT_URI'],
       cookieSecret:  $_ENV['ZITADEL_COOKIE_SECRET'],
       protectAll:    true,
       ignoredRoutes: ['/health'],
   );

   $app = AppFactory::create();
   $app->add(new ZitadelMiddleware($config, new TokenValidator($config, new JwksCache()), $psr17));

   $app->get('/dashboard', function (Request $request, Response $response): Response {
       /** @var \Zitadel\Sdk\Auth\Claims|null $claims */
       $claims = $request->getAttribute('zitadel.claims');
       $response->getBody()->write("Hello {$claims?->name}");
       return $response;
   });

   $app->run();

The middleware must be added via ``$app->add()`` (not inside a route group) so it
runs before Slim's router and can intercept the callback and logout paths.


Protecting Routes
-----------------

Protect all routes (recommended)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Set ``protectAll`` to ``true`` and list public paths in ``ignoredRoutes``:

.. code-block:: php

   $config = new ZitadelConfig(
       // ...
       protectAll:    true,
       ignoredRoutes: ['/health', '/api/public/*'],
   );

Protect specific routes
~~~~~~~~~~~~~~~~~~~~~~~

Leave ``protectAll`` unset (defaults to ``false``) and enumerate paths in
``protectedRoutes``:

.. code-block:: php

   $config = new ZitadelConfig(
       // ...
       protectedRoutes: ['/dashboard*', '/admin*'],
   );


Accessing Claims
----------------

:php:class:`Zitadel\Sdk\Auth\Claims` are attached as a PSR-7 request attribute under
the key ``"zitadel.claims"``:

.. code-block:: php

   /** @var \Zitadel\Sdk\Auth\Claims|null $claims */
   $claims = $request->getAttribute('zitadel.claims');

All properties are available: ``$claims->sub``, ``$claims->name``, ``$claims->email``,
``$claims->payload``, and so on.


Opting Out
----------

Per-path (configuration)
~~~~~~~~~~~~~~~~~~~~~~~~

Add paths to ``ignoredRoutes`` when constructing
:php:class:`Zitadel\Sdk\Config\ZitadelConfig`:

.. code-block:: php

   $config = new ZitadelConfig(
       // ...
       ignoredRoutes: ['/health', '/public/*', '/login'],
   );

Per-route (``#[AllowAnonymous]``)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

:php:class:`Zitadel\Sdk\Attribute\AllowAnonymous` is **not supported** in Slim 4.

The ``#[AllowAnonymous]`` check in :php:class:`Zitadel\Sdk\Middleware\ZitadelMiddleware`
works by reading the ``Mezzio\Router\RouteResult`` request attribute, which is set by
Mezzio's ``RouteMiddleware`` after routing resolves. Slim does not set this attribute,
so reflection never fires regardless of middleware placement.

Use ``ignoredRoutes`` to exempt specific paths:

.. code-block:: php

   $config = new ZitadelConfig(
       // ...
       ignoredRoutes: ['/health', '/status', '/api/public/*'],
   );


Forwarding Tokens
-----------------

:php:attr:`Zitadel\Sdk\Auth\Claims::$token` contains the raw signed JWT. Forward it as
a ``Bearer`` token to any downstream service that validates JWTs independently:

.. code-block:: php

   $app->get('/orders', function (Request $request, Response $response): Response {
       /** @var \Zitadel\Sdk\Auth\Claims|null $claims */
       $claims = $request->getAttribute('zitadel.claims');

       $downstream = $httpClient->get('https://api.internal/v1/orders', [
           'headers' => ['Authorization' => 'Bearer ' . $claims?->token],
       ]);

       $response->getBody()->write($downstream->getBody()->getContents());
       return $response->withHeader('Content-Type', 'application/json');
   });


Using a DI Container
--------------------

For larger applications, bind the middleware in a container rather than constructing
it inline. The following example uses PHP-DI:

.. code-block:: php

   use DI\ContainerBuilder;
   use Nyholm\Psr7\Factory\Psr17Factory;
   use Psr\Http\Message\ResponseFactoryInterface;
   use Slim\Factory\AppFactory;
   use Zitadel\Sdk\Auth\JwksCache;
   use Zitadel\Sdk\Auth\TokenValidator;
   use Zitadel\Sdk\Config\ZitadelConfig;
   use Zitadel\Sdk\Middleware\ZitadelMiddleware;

   $builder = new ContainerBuilder();
   $builder->addDefinitions([
       ResponseFactoryInterface::class => \DI\create(Psr17Factory::class),
       ZitadelConfig::class => \DI\create(ZitadelConfig::class)->constructor(
           issuerUrl:    $_ENV['ZITADEL_ISSUER_URL'],
           clientId:     $_ENV['ZITADEL_CLIENT_ID'],
           redirectUri:  $_ENV['ZITADEL_REDIRECT_URI'],
           cookieSecret: $_ENV['ZITADEL_COOKIE_SECRET'],
           protectAll:   true,
       ),
       JwksCache::class         => \DI\create(JwksCache::class),
       TokenValidator::class    => \DI\autowire(),
       ZitadelMiddleware::class => \DI\autowire(),
   ]);

   $container = $builder->build();
   AppFactory::setContainer($container);

   $app = AppFactory::create();
   $app->add(ZitadelMiddleware::class);
