<?php

declare(strict_types=1);

use Phalcon\Di\FactoryDefault;
use Phalcon\Events\Manager as EventsManager;
use Phalcon\Mvc\Application;
use Zitadel\Sdk\Auth\JwksCache;
use Zitadel\Sdk\Auth\TokenValidator;
use Zitadel\Sdk\Bridge\Phalcon\ZitadelPlugin;
use Zitadel\Sdk\Config\ZitadelConfig;

require_once __DIR__ . '/../vendor/autoload.php';

$dotenv = Dotenv\Dotenv::createImmutable(__DIR__ . '/../');
$dotenv->load();

$di = new FactoryDefault();

$config = new ZitadelConfig(
    issuerUrl:    $_ENV['ZITADEL_ISSUER_URL'],
    clientId:     $_ENV['ZITADEL_CLIENT_ID'],
    redirectUri:  $_ENV['ZITADEL_REDIRECT_URI'],
    cookieSecret: $_ENV['ZITADEL_COOKIE_SECRET'],
    protectAll:   true,
    ignoredRoutes: ['/health'],
);

$validator = new TokenValidator($config, new JwksCache());
$plugin    = new ZitadelPlugin($config, $validator);

$eventsManager = new EventsManager();
$eventsManager->attach('application', $plugin);
$eventsManager->attach('dispatch', $plugin);

$app = new Application($di);
$app->setEventsManager($eventsManager);
$app->getDI()->get('dispatcher')->setEventsManager($eventsManager);

$result = $app->handle($_SERVER['REQUEST_URI']);
if ($result !== false) {
    echo $result->getContent();
}
