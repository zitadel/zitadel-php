<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use Zitadel\Sdk\Bridge\Laravel\Http\Controllers\CallbackController;
use Zitadel\Sdk\Bridge\Laravel\Http\Controllers\LogoutController;
use Zitadel\Sdk\Bridge\Laravel\Http\Controllers\ProxyController;
use Zitadel\Sdk\Config\ZitadelConfig;

/** @var ZitadelConfig $config */
$config = app(ZitadelConfig::class);

Route::get($config->callbackPath, CallbackController::class)->name('zitadel.callback');
Route::get($config->logoutPath, LogoutController::class)->name('zitadel.logout');

// Proxy: exact match (e.g. /__nextgen) and wildcard sub-paths (e.g. /__nextgen/oauth/v2/keys).
// The ProxyController handles the actual forwarding; ZitadelMiddleware skips auth for this prefix.
Route::any($config->proxyPath, ProxyController::class)->name('zitadel.proxy');
Route::any($config->proxyPath . '/{path}', ProxyController::class)
    ->name('zitadel.proxy.sub')
    ->where('path', '.+');
