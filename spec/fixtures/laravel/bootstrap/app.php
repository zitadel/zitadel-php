<?php

declare(strict_types=1);

use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__ . '/../routes/web.php',
    )
    ->withMiddleware(function (Middleware $middleware) {
        // Cookie encryption for __nextgen_auth and __nextgen_pkce is excluded automatically
        // by ZitadelServiceProvider::boot() — no manual configuration needed here.
    })
    ->withExceptions(function (Exceptions $exceptions) {
        //
    })
    ->create();
