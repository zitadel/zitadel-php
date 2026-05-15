<?php

declare(strict_types=1);

use Phalcon\Di\FactoryDefault;
use Phalcon\Events\Manager as EventsManager;
use Phalcon\Autoload\Loader;
use Phalcon\Mvc\Application;
use Phalcon\Mvc\View;
use Zitadel\Sdk\Bridge\Phalcon\ZitadelServiceProvider;
use Zitadel\Sdk\Config\ZitadelConfig;

require_once __DIR__ . '/../vendor/autoload.php';

$dotenv = Dotenv\Dotenv::createImmutable(__DIR__ . '/../');
$dotenv->safeLoad();

// Autoload controllers
(new Loader())
    ->setDirectories([__DIR__ . '/../app/controllers/'])
    ->register();

$di = new FactoryDefault();

// Minimal view service (prevents "Phalcon\Mvc\View service must be set" error)
$di->set('view', fn () => new View(), true);

// Router
$di->set('router', function () {
    return require __DIR__ . '/../app/config/router.php';
}, true);

ZitadelServiceProvider::register($di, new ZitadelConfig(
    issuerUrl:         (string) ($_ENV['ZITADEL_ISSUER_URL']         ?? ''),
    clientId:          (string) ($_ENV['ZITADEL_CLIENT_ID']          ?? ''),
    redirectUri:       (string) ($_ENV['ZITADEL_REDIRECT_URI']       ?? ''),
    cookieSecret:      (string) ($_ENV['ZITADEL_COOKIE_SECRET']      ?? ''),
    protectAll:        true,
    ignoredRoutes:     ['/health'],
    jwksPath:          (string) ($_ENV['ZITADEL_JWKS_PATH']          ?? '/oauth/v2/keys'),
    authorizationPath: (string) ($_ENV['ZITADEL_AUTHORIZATION_PATH'] ?? '/oauth/v2/authorize'),
    tokenPath:         (string) ($_ENV['ZITADEL_TOKEN_PATH']         ?? '/oauth/v2/token'),
    endSessionPath:    (string) ($_ENV['ZITADEL_END_SESSION_PATH']   ?? '/oidc/v1/end_session'),
));

$plugin = $di->get('zitadelPlugin');

$eventsManager = new EventsManager();
$eventsManager->attach('application', $plugin);
$eventsManager->attach('dispatch',    $plugin);

$app = new Application($di);
$app->setEventsManager($eventsManager);
$app->getDI()->get('dispatcher')->setEventsManager($eventsManager);

$result = $app->handle($_SERVER['REQUEST_URI']);
if ($result !== false) {
    echo $result->getContent();
}
