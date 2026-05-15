<?php

declare(strict_types=1);

use CodeIgniter\Router\RouteCollection;

/** @var RouteCollection $routes */
$routes->get('/dashboard',          'Dashboard::index');
$routes->get('/health',             'Health::index');
$routes->get('/home',               'Home::index');
$routes->get('/api',                'Api::index');
