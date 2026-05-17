<?php

declare(strict_types=1);

use App\Http\Controllers\ApiController;
use App\Http\Controllers\DashboardController;
use App\Http\Controllers\HealthController;
use App\Http\Controllers\HomeController;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use Zitadel\Sdk\Event\ZitadelLoginEvent;
use Zitadel\Sdk\Event\ZitadelLogoutEvent;

Event::listen(ZitadelLoginEvent::class,  static fn () => error_log('[ZITADEL_EVENT] ZitadelLoginEvent'));
Event::listen(ZitadelLogoutEvent::class, static fn () => error_log('[ZITADEL_EVENT] ZitadelLogoutEvent'));

Route::get('/health', HealthController::class)->name('health');
Route::get('/home', HomeController::class)->name('home');
Route::get('/api', ApiController::class)->name('api');
Route::get('/dashboard', DashboardController::class)->name('dashboard');
