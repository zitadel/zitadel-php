<?php

declare(strict_types=1);

use CodeIgniter\Router\RouteCollection;

/** @var RouteCollection $routes */
$routes->get('/dashboard',          'Dashboard::index');
$routes->get('/health',             'Health::index');
$routes->get('/home',               'Home::index');
$routes->get('/api',                'Api::index');
// These paths are intercepted by ZitadelFilterWrapper before the controller runs.
// Routes must exist for CI4 to run before-filters; controller is never reached.
$routes->get('/zitadel/callback',   'Health::index');
$routes->get('/zitadel/logout',     'Health::index');
