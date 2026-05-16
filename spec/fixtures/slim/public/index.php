<?php

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use Nyholm\Psr7\Factory\Psr17Factory;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Factory\AppFactory;
use Zitadel\Sdk\Auth\Claims;
use Zitadel\Sdk\Auth\JwksCache;
use Zitadel\Sdk\Auth\TokenValidator;
use Zitadel\Sdk\Config\ZitadelConfig;
use Zitadel\Sdk\Middleware\ZitadelMiddleware;

$dotenv = Dotenv\Dotenv::createImmutable(__DIR__ . '/..');
$dotenv->safeLoad();

$factory = new Psr17Factory();

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

$cache      = new JwksCache();
$validator  = new TokenValidator($config, $cache);
$middleware = new ZitadelMiddleware($config, $validator, $factory);

AppFactory::setResponseFactory($factory);
$app = AppFactory::create();

// Slim processes middleware in LIFO order (last added runs first). ZitadelMiddleware
// must be outermost so it intercepts callback, logout, and proxy paths before Slim's
// routing middleware has a chance to 404 them. Add it LAST so it runs FIRST.
$app->addRoutingMiddleware();
$app->add($middleware);

$app->get('/health', function (ServerRequestInterface $request, ResponseInterface $response): ResponseInterface {
    $response->getBody()->write('OK');

    return $response->withHeader('Content-Type', 'text/plain');
});

$app->get('/home', function (ServerRequestInterface $request, ResponseInterface $response): ResponseInterface {
    $response->getBody()->write('Welcome home');

    return $response->withHeader('Content-Type', 'text/plain');
});

$app->get('/dashboard', function (ServerRequestInterface $request, ResponseInterface $response): ResponseInterface {
    /** @var Claims|null $claims */
    $claims = $request->getAttribute('zitadel.claims');
    $response->getBody()->write("Hello {$claims?->name}\nemail:{$claims?->email}\nsub:{$claims?->sub}");

    return $response->withHeader('Content-Type', 'text/plain');
});

$app->get('/api', function (ServerRequestInterface $request, ResponseInterface $response): ResponseInterface {
    /** @var Claims|null $claims */
    $claims  = $request->getAttribute('zitadel.claims');
    $payload = $claims !== null
        ? ['authenticated' => true, 'sub' => $claims->sub, 'name' => $claims->name, 'email' => $claims->email]
        : ['authenticated' => false];
    $response->getBody()->write((string) json_encode($payload));

    return $response->withHeader('Content-Type', 'application/json');
});

$app->run();
