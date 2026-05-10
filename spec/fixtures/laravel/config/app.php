<?php

declare(strict_types=1);

return [
    'name'     => env('APP_NAME', 'ZitadelFixture'),
    'env'      => env('APP_ENV', 'local'),
    'debug'    => (bool) env('APP_DEBUG', false),
    'url'      => env('APP_URL', 'http://localhost'),
    'key'      => env('APP_KEY'),
    'cipher'   => 'AES-256-CBC',
    'timezone' => 'UTC',
    'locale'   => 'en',
    'providers' => \Illuminate\Support\ServiceProvider::defaultProviders()->toArray(),
    'aliases'   => \Illuminate\Support\Facades\Facade::defaultAliases()->toArray(),
];
