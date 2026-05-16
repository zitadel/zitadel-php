<?php

declare(strict_types=1);

use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;
use Zitadel\Sdk\Bridge\Laravel\Http\Middleware\ZitadelMiddleware;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__ . '/../routes/web.php',
    )
    ->withMiddleware(fn (Middleware $middleware) => $middleware->web(append: [ZitadelMiddleware::class]))
    ->withExceptions(function (Exceptions $exceptions) {
        //
    })
    ->create();
