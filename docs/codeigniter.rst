CodeIgniter 4
=============

The CodeIgniter 4 bridge uses the framework's native ``FilterInterface`` to intercept
requests before routing. Because CI4's ``IncomingRequest`` does not support arbitrary
attributes (unlike PSR-7 or Symfony's ``ParameterBag``), validated claims are stored in
the static :php:class:`Zitadel\Sdk\Bridge\CodeIgniter\ZitadelHolder` and retrieved in
controllers via ``ZitadelHolder::claims()``.

.. note::

   Requires CodeIgniter 4.3+.


Installation
------------

.. code-block:: bash

   composer require zitadel/sdk


Environment Variables
---------------------

CI4 reads ``.env`` automatically when the file exists in the project root:

.. code-block:: ini

   ZITADEL_ISSUER_URL=https://my.zitadel.cloud
   ZITADEL_CLIENT_ID=your-client-id
   ZITADEL_COOKIE_SECRET=
   SERVER_URL=https://myapp.com
   ZITADEL_PROTECT_ALL=true

Generate a secure cookie secret (64 hex characters):

.. code-block:: bash

   php -r "echo bin2hex(random_bytes(32)) . PHP_EOL;"

The redirect URI is derived automatically as ``SERVER_URL + /zitadel/callback``.
Set ``ZITADEL_REDIRECT_URI`` explicitly only if you need to override this.
Register the computed URI as the allowed callback in your Zitadel application settings.


Configuration
-------------

Run the publish command once to create ``app/Config/Zitadel.php``:

.. code-block:: bash

   php spark zitadel:publish

The generated file is an intentionally empty subclass. All settings are read from
environment variables, so the file only exists to let CI4 resolve it by short name.
Add properties here only to override a value in code instead of via ``.env``:

.. code-block:: php

   namespace Config;

   use Zitadel\Sdk\Bridge\CodeIgniter\Config\Zitadel as BaseZitadel;

   class Zitadel extends BaseZitadel
   {
       public array $ignoredRoutes = ['/health', '/public/*'];
   }

That is everything. No changes to ``Services.php`` or ``Filters.php`` are needed:

- **Filter auto-registration** — the SDK ships a ``Config\Registrar`` class that CI4
  discovers automatically (via ``Config\Modules::$discoverInComposer``, on by default
  in all CI4 4.x projects). It registers :php:class:`Zitadel\Sdk\Bridge\CodeIgniter\ZitadelFilter`
  as a global ``before`` filter without any edits to your ``app/Config/Filters.php``.

- **Self-configuration** — when CI4 instantiates ``ZitadelFilter`` with no constructor
  arguments, the filter calls ``config('Zitadel')`` internally to build its own
  ``ZitadelConfig`` value object. Your ``app/Config/Zitadel.php`` subclass is resolved
  first; the SDK base class defaults serve as the fallback.

No custom routes are needed. When the filter handles the callback or logout path, it
returns a ``ResponseInterface`` directly, short-circuiting CI4's dispatch pipeline
before the router runs.


Protecting Routes
-----------------

Protect all routes (recommended)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Set ``ZITADEL_PROTECT_ALL=true`` in ``.env``. Public paths are exempted via
``$ignoredRoutes`` or the ``#[AllowAnonymous]`` attribute (see *Opting Out* below):

.. code-block:: ini

   ZITADEL_PROTECT_ALL=true

To hard-code the setting instead of using an env var, set it in ``app/Config/Zitadel.php``:

.. code-block:: php

   class Zitadel extends BaseZitadel
   {
       public bool  $protectAll    = true;
       public array $ignoredRoutes = ['/health', '/public/*'];
   }

Protect specific routes
~~~~~~~~~~~~~~~~~~~~~~~

Leave ``ZITADEL_PROTECT_ALL`` unset (defaults to ``false``) and enumerate protected
paths in ``$protectedRoutes`` in ``app/Config/Zitadel.php``:

.. code-block:: php

   class Zitadel extends BaseZitadel
   {
       public array $protectedRoutes = ['/dashboard*', '/admin*'];
   }


Accessing Claims
----------------

After successful token validation,
:php:class:`Zitadel\Sdk\Bridge\CodeIgniter\ZitadelFilter` stores the
:php:class:`Zitadel\Sdk\Auth\Claims` in
:php:class:`Zitadel\Sdk\Bridge\CodeIgniter\ZitadelHolder`. Retrieve it in any
controller via the static ``claims()`` method:

.. code-block:: php

   use App\Controllers\BaseController;
   use Zitadel\Sdk\Bridge\CodeIgniter\ZitadelHolder;

   class Dashboard extends BaseController
   {
       public function index(): string
       {
           $claims = ZitadelHolder::claims();

           return view('dashboard/index', [
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

Add paths to ``$ignoredRoutes`` in ``app/Config/Zitadel.php``. Entries ending with
``*`` are treated as prefix wildcards:

.. code-block:: php

   class Zitadel extends BaseZitadel
   {
       public array $ignoredRoutes = ['/health', '/public/*'];
   }

Per-controller or per-method
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

:php:class:`Zitadel\Sdk\Attribute\AllowAnonymous` is supported. CI4 filters run after
routing, so ``service('router')->getController()`` returns the fully-qualified class
name and ``service('router')->methodName()`` returns the method name. The filter
reflects on both for the attribute:

.. code-block:: php

   use Zitadel\Sdk\Attribute\AllowAnonymous;

   class Health extends BaseController
   {
       #[AllowAnonymous]
       public function index(): string
       {
           return 'OK';
       }
   }



Forwarding Tokens
-----------------

:php:attr:`Zitadel\Sdk\Auth\Claims::$token` contains the raw signed JWT. Forward it as
a ``Bearer`` token to any downstream service that validates JWTs independently:

.. code-block:: php

   use CodeIgniter\HTTP\CURLRequest;
   use Zitadel\Sdk\Bridge\CodeIgniter\ZitadelHolder;

   class Orders extends BaseController
   {
       public function index(): string
       {
           $claims = ZitadelHolder::claims();

           /** @var CURLRequest $client */
           $client   = service('curlrequest');
           $response = $client->get('https://api.internal/v1/orders', [
               'headers' => ['Authorization' => 'Bearer ' . $claims?->token],
           ]);

           return $response->getBody();
       }
   }


Long-Running Runtimes
---------------------

On runtimes where the PHP process persists across requests (Swoole, RoadRunner,
FrankenPHP), the static holder retains its value from the previous request. Reset it
at the start of each request lifecycle:

.. code-block:: php

   use Zitadel\Sdk\Bridge\CodeIgniter\ZitadelHolder;

   // In your Swoole on-request callback or RoadRunner worker loop,
   // before dispatching each new request:
   ZitadelHolder::set(null);

This mirrors the pattern used by CI4's own ``Services::reset()`` for per-request
service resetting on long-running runtimes.


Why ``ZitadelHolder``?
----------------------

CI4's ``IncomingRequest`` does not support arbitrary attributes (unlike PSR-7's
``ServerRequestInterface::withAttribute()`` or Symfony's ``ParameterBag``). Storing
claims in server-side sessions would require persistent storage and contradict the
library's zero-session design. The static holder is therefore the only viable mechanism
for passing claims from a filter to a controller within the same PHP request lifecycle
on standard CI4.
