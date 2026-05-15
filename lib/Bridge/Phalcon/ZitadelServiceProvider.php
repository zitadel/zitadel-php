<?php

declare(strict_types=1);

namespace Zitadel\Sdk\Bridge\Phalcon;

use Phalcon\Di\DiInterface;
use Zitadel\Sdk\Auth\JwksCache;
use Zitadel\Sdk\Auth\TokenValidator;
use Zitadel\Sdk\Config\ZitadelConfig;

/**
 * Registers all Zitadel SDK services in the Phalcon DI container.
 *
 * Call {@see register()} once during bootstrap — typically in `public/index.php`
 * before the application handles the request. After registration the plugin is
 * available via `$di->get('zitadelPlugin')` and can be attached to any events
 * manager:
 *
 * ```php
 * ZitadelServiceProvider::register($di, new ZitadelConfig(...));
 *
 * $plugin = $di->get('zitadelPlugin');
 * $eventsManager->attach('application', $plugin);
 * $eventsManager->attach('dispatch',    $plugin);
 * ```
 *
 * Registered services:
 * - `zitadelConfig`    — the {@see ZitadelConfig} instance passed to `register()`
 * - `zitadelValidator` — a shared {@see TokenValidator} backed by a {@see JwksCache}
 * - `zitadelPlugin`    — a shared {@see ZitadelPlugin} wired to the config and validator
 */
final class ZitadelServiceProvider
{
    private function __construct()
    {
    }

    /**
     * Registers Zitadel SDK services as shared bindings in `$di`.
     *
     * @param DiInterface   $di     The Phalcon DI container to register services into.
     * @param ZitadelConfig $config The SDK configuration for this application.
     */
    public static function register(DiInterface $di, ZitadelConfig $config): void
    {
        $di->setShared('zitadelConfig', $config);

        $di->setShared('zitadelValidator', fn () => new TokenValidator($config, new JwksCache()));

        $di->setShared('zitadelPlugin', fn () => new ZitadelPlugin($config, $di->get('zitadelValidator')));
    }
}
