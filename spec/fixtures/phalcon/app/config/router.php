<?php

declare(strict_types=1);

use Phalcon\Mvc\Router;

$router = new Router(false);
$router->add('/dashboard', ['controller' => 'dashboard', 'action' => 'index']);
$router->add('/health',    ['controller' => 'health',    'action' => 'index']);

return $router;
