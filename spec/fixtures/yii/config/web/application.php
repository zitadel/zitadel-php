<?php

declare(strict_types=1);

use App\Action\DashboardAction;
use App\Action\HealthAction;
use Yiisoft\Router\Middleware\Router;
use Yiisoft\Router\Route;
use Zitadel\Sdk\Middleware\ZitadelMiddleware;

return [
    'middlewares' => [
        ZitadelMiddleware::class,
        Router::class,
    ],

    'routes' => [
        Route::get('/dashboard')->action(DashboardAction::class)->name('dashboard'),
        Route::get('/health')->action(HealthAction::class)->name('health'),
    ],
];
