Symfony
=======

The Symfony bridge integrates via a Bundle that subscribes to
``KernelEvents::REQUEST`` (before routing) and ``KernelEvents::CONTROLLER``
(after routing). A ``ValueResolverInterface`` implementation auto-injects
``?Claims $claims`` into controller parameters with no additional wiring.

.. note::

   Supports Symfony 6.4 and 7.x.


Installation
------------

.. code-block:: bash

   composer require zitadel/zitadel-php

Register the bundle in ``config/bundles.php``:

.. code-block:: php

   return [
       // ...
       Zitadel\Sdk\Bridge\Symfony\ZitadelBundle::class => ['all' => true],
   ];


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

Create ``config/packages/zitadel.yaml``:

.. code-block:: yaml

   zitadel:
       issuer_url:    '%env(ZITADEL_ISSUER_URL)%'
       client_id:     '%env(ZITADEL_CLIENT_ID)%'
       redirect_uri:  '%env(ZITADEL_REDIRECT_URI)%'
       cookie_secret: '%env(ZITADEL_COOKIE_SECRET)%'
       protect_all:   true
       ignored_routes:
           - '/health'

All keys map directly to :php:class:`Zitadel\Sdk\Config\ZitadelConfig` constructor
parameters (``camelCase`` → ``snake_case``). See the :doc:`index` configuration
reference for the full list.


Protecting Routes
-----------------

Protect all routes (recommended)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Set ``protect_all: true`` and list public paths in ``ignored_routes``:

.. code-block:: yaml

   zitadel:
       protect_all: true
       ignored_routes:
           - '/health'
           - '/api/public/*'

Protect specific routes
~~~~~~~~~~~~~~~~~~~~~~~

Leave ``protect_all`` unset (defaults to ``false``) and enumerate paths in
``protected_routes``:

.. code-block:: yaml

   zitadel:
       protected_routes:
           - '/dashboard*'
           - '/admin*'
           - '/api/v1*'


Accessing Claims
----------------

:php:class:`Zitadel\Sdk\Bridge\Symfony\ArgumentResolver\ClaimsValueResolver` is
auto-tagged as ``controller.argument_value_resolver`` when the DI container is
compiled. Type-hint ``?Claims`` in any controller action and it resolves
automatically — no ``#[MapRequestPayload]`` or manual wiring needed:

.. code-block:: php

   use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
   use Symfony\Component\HttpFoundation\Response;
   use Symfony\Component\Routing\Annotation\Route;
   use Zitadel\Sdk\Auth\Claims;

   class DashboardController extends AbstractController
   {
       #[Route('/dashboard')]
       public function index(?Claims $claims): Response
       {
           return $this->render('dashboard/index.html.twig', [
               'name'  => $claims?->name,
               'email' => $claims?->email,
               'sub'   => $claims?->sub,
           ]);
       }
   }

Type-hint as ``?Claims`` (nullable) even on protected routes. The middleware redirects
unauthenticated requests before the controller runs, so ``$claims`` is never ``null``
on a protected path.

If you prefer imperative access, read from Symfony's ``ParameterBag``:

.. code-block:: php

   use Symfony\Component\HttpFoundation\Request;
   use Zitadel\Sdk\Auth\Claims;

   public function index(Request $request): Response
   {
       /** @var Claims|null $claims */
       $claims = $request->attributes->get('zitadel.claims');
   }


Opting Out
----------

Per-path (configuration)
~~~~~~~~~~~~~~~~~~~~~~~~

Add paths to ``ignored_routes`` in ``config/packages/zitadel.yaml``:

.. code-block:: yaml

   zitadel:
       ignored_routes:
           - '/health'
           - '/api/public/*'

Per-controller or per-method
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

:php:class:`Zitadel\Sdk\Attribute\AllowAnonymous` marks a controller class or action
method as publicly accessible.
:php:class:`Zitadel\Sdk\Bridge\Symfony\EventListener\ZitadelListener` reflects on the
resolved controller at ``KernelEvents::CONTROLLER`` (priority 0) and allows the request
through even on protected paths:

.. code-block:: php

   use Symfony\Component\Routing\Annotation\Route;
   use Zitadel\Sdk\Attribute\AllowAnonymous;
   use Zitadel\Sdk\Auth\Claims;

   class ApiController extends AbstractController
   {
       // Public — no session required
       #[Route('/api/status')]
       #[AllowAnonymous]
       public function status(): Response
       {
           return new JsonResponse(['status' => 'ok']);
       }

       // Protected — $claims is non-null (middleware redirected if absent)
       #[Route('/api/me')]
       public function me(?Claims $claims): Response
       {
           return new JsonResponse(['sub' => $claims?->sub]);
       }
   }

.. note::

   ``#[AllowAnonymous]`` works because ``KernelEvents::CONTROLLER`` fires after routing
   resolves the controller, giving the listener access to the class and method for
   reflection. It handles array callables ``[$object, 'method']``, invokable objects,
   and class-level attributes.


Forwarding Tokens
-----------------

:php:attr:`Zitadel\Sdk\Auth\Claims::$token` contains the raw signed JWT. Forward it as
a ``Bearer`` token to any downstream service that validates JWTs independently:

.. code-block:: php

   use Symfony\Contracts\HttpClient\HttpClientInterface;
   use Zitadel\Sdk\Auth\Claims;

   class OrdersController extends AbstractController
   {
       public function __construct(
           private readonly HttpClientInterface $httpClient,
       ) {}

       #[Route('/orders')]
       public function index(?Claims $claims): Response
       {
           $response = $this->httpClient->request('GET', 'https://api.internal/v1/orders', [
               'headers' => ['Authorization' => 'Bearer ' . $claims?->token],
           ]);
           return $this->json($response->toArray());
       }
   }


Architecture Note
-----------------

The bridge deliberately does **not** integrate with ``symfony/security-bundle`` via
``AbstractAuthenticator`` and firewall configuration. The library owns the complete
PKCE flow (redirect → callback → cookie), and plugging into the security firewall
would require implementing ``UserProviderInterface``, ``PassportInterface``, and YAML
firewall config with no practical benefit for this use case.

``KernelEvents::REQUEST`` at priority 33 is a well-established pattern for pre-routing
intercepts (the ``RouterListener`` runs at priority 32; the Zitadel listener fires one
step before it). ``ClaimsValueResolver`` is the idiomatic Symfony 6+ pattern for
request-derived controller parameters, analogous to Symfony's own ``UserValueResolver``
for ``#[CurrentUser]``.

If you need ``isGranted()`` or role-based access control, implement a custom
``UserProvider`` on top of the :php:class:`Zitadel\Sdk\Auth\Claims` object from the
request attributes. The ``$payload`` array on ``Claims`` carries all raw JWT claims
including Zitadel roles.
