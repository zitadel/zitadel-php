<?php

declare(strict_types=1);

use App\Http\Controllers\ApiController;
use App\Http\Controllers\DashboardController;
use App\Http\Controllers\HealthController;
use App\Http\Controllers\HomeController;
use Illuminate\Support\Facades\Route;

Route::get('/health', HealthController::class)->name('health');
Route::get('/home', HomeController::class)->name('home');
Route::get('/api', ApiController::class)->name('api');
Route::get('/dashboard', DashboardController::class)->name('dashboard');
