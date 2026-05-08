<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use Zitadel\Sdk\Bridge\Laravel\Http\Controllers\CallbackController;
use Zitadel\Sdk\Bridge\Laravel\Http\Controllers\LogoutController;
use Zitadel\Sdk\Config\ZitadelConfig;

/** @var ZitadelConfig $config */
$config = app(ZitadelConfig::class);

Route::get($config->callbackPath, CallbackController::class)->name('zitadel.callback');
Route::get($config->logoutPath, LogoutController::class)->name('zitadel.logout');
