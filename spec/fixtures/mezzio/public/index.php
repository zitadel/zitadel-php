<?php

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use Laminas\Diactoros\ResponseFactory;
use Laminas\Diactoros\ServerRequestFactory;
use Mezzio\Router\FastRouteRouter;
use Mezzio\Router\Route;
use Mezzio\Router\RouteResult;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Zitadel\Sdk\Auth\Claims;
use Zitadel\Sdk\Auth\JwksCache;
use Zitadel\Sdk\Auth\TokenValidator;
use Zitadel\Sdk\Config\ZitadelConfig;
use Zitadel\Sdk\Middleware\ZitadelMiddleware;

$dotenv = Dotenv\Dotenv::createImmutable(__DIR__ . '/..');
$dotenv->safeLoad();

$factory = new ResponseFactory();

$config = new ZitadelConfig(
    issuerUrl:         (string) ($_ENV['ZITADEL_ISSUER_URL']         ?? ''),
    clientId:          (string) ($_ENV['ZITADEL_CLIENT_ID']          ?? ''),
    redirectUri:       (string) ($_ENV['ZITADEL_REDIRECT_URI']       ?? ''),
    cookieSecret:      (string) ($_ENV['ZITADEL_COOKIE_SECRET']      ?? ''),
    audience:          ($_ENV['ZITADEL_AUDIENCE'] ?? null) ?: null,
    protectAll:        false,
    protectedRoutes:   ['/dashboard'],
    ignoredRoutes:     ['/health'],
    jwksPath:          (string) ($_ENV['ZITADEL_JWKS_PATH']          ?? '/oauth/v2/keys'),
    authorizationPath: (string) ($_ENV['ZITADEL_AUTHORIZATION_PATH'] ?? '/oauth/v2/authorize'),
    tokenPath:         (string) ($_ENV['ZITADEL_TOKEN_PATH']         ?? '/oauth/v2/token'),
    endSessionPath:    (string) ($_ENV['ZITADEL_END_SESSION_PATH']   ?? '/oidc/v1/end_session'),
);

$cache     = new JwksCache();
$validator = new TokenValidator($config, $cache);
$zitadel   = new ZitadelMiddleware($config, $validator, $factory);

// ── Route handlers ─────────────────────────────────────────────────────────

$healthHandler = new class($factory) implements MiddlewareInterface {
    public function __construct(private readonly ResponseFactory $factory) {}

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $response = $this->factory->createResponse(200);
        $response->getBody()->write('OK');

        return $response->withHeader('Content-Type', 'text/plain');
    }
};

$homeHandler = new class($factory) implements MiddlewareInterface {
    public function __construct(private readonly ResponseFactory $factory) {}

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $response = $this->factory->createResponse(200);
        $response->getBody()->write('Welcome home');

        return $response->withHeader('Content-Type', 'text/plain');
    }
};

$dashboardHandler = new class($factory) implements MiddlewareInterface {
    public function __construct(private readonly ResponseFactory $factory) {}

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        /** @var Claims|null $claims */
        $claims   = $request->getAttribute('zitadel.claims');
        $response = $this->factory->createResponse(200);
        $response->getBody()->write("Hello {$claims?->name}\nemail:{$claims?->email}\nsub:{$claims?->sub}");

        return $response->withHeader('Content-Type', 'text/plain');
    }
};

$apiHandler = new class($factory) implements MiddlewareInterface {
    public function __construct(private readonly ResponseFactory $factory) {}

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        /** @var Claims|null $claims */
        $claims   = $request->getAttribute('zitadel.claims');
        $payload  = $claims !== null
            ? ['authenticated' => true, 'sub' => $claims->sub, 'name' => $claims->name, 'email' => $claims->email]
            : ['authenticated' => false];
        $response = $this->factory->createResponse(200);
        $response->getBody()->write((string) json_encode($payload));

        return $response->withHeader('Content-Type', 'application/json');
    }
};

// ── Router ─────────────────────────────────────────────────────────────────

$router = new FastRouteRouter();
$router->addRoute(new Route('/health',    $healthHandler,    ['GET'], 'health'));
$router->addRoute(new Route('/home',      $homeHandler,      ['GET'], 'home'));
$router->addRoute(new Route('/dashboard', $dashboardHandler, ['GET'], 'dashboard'));
$router->addRoute(new Route('/api',       $apiHandler,       ['GET'], 'api'));

// Match the incoming request and attach the RouteResult attribute so the generic
// ZitadelMiddleware can use it for #[AllowAnonymous] reflection (step 6a).
$request     = ServerRequestFactory::fromGlobals();
$routeResult = $router->match($request);
$request     = $request->withAttribute(RouteResult::class, $routeResult);

// ── Terminal handler ───────────────────────────────────────────────────────

// Dispatches to the matched route handler. Called by ZitadelMiddleware when the
// request passes auth checks (or is on a public/ignored route).
$terminalHandler = new class($factory) implements RequestHandlerInterface {
    public function __construct(private readonly ResponseFactory $factory) {}

    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $result = $request->getAttribute(RouteResult::class);

        if (!$result instanceof RouteResult || !$result->isSuccess()) {
            $response = $this->factory->createResponse(404);
            $response->getBody()->write('Not Found');

            return $response->withHeader('Content-Type', 'text/plain');
        }

        return $result->getMatchedRoute()->getMiddleware()->process($request, $this);
    }
};

// ── Run ────────────────────────────────────────────────────────────────────

$response = $zitadel->process($request, $terminalHandler);

http_response_code($response->getStatusCode());
foreach ($response->getHeaders() as $name => $values) {
    foreach ($values as $value) {
        header("{$name}: {$value}", false);
    }
}
echo $response->getBody();
