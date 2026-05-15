<?php

declare(strict_types=1);

use Phalcon\Events\Manager as EventsManager;
use Phalcon\Autoload\Loader;
use Phalcon\Mvc\Application;

require_once __DIR__ . '/../vendor/autoload.php';

$dotenv = Dotenv\Dotenv::createImmutable(__DIR__ . '/../');
$dotenv->safeLoad();

// Autoload controllers
(new Loader())
    ->setDirectories([__DIR__ . '/../app/controllers/'])
    ->register();

$di     = require __DIR__ . '/../app/config/services.php';
$plugin = $di->get('zitadelPlugin');

$eventsManager = new EventsManager();
$eventsManager->attach('application', $plugin);
$eventsManager->attach('dispatch',    $plugin);

$app = new Application($di);
$app->setEventsManager($eventsManager);
$app->getDI()->get('dispatcher')->setEventsManager($eventsManager);

$result = $app->handle($_SERVER['REQUEST_URI']);
if ($result !== false) {
    $result->send();
}
