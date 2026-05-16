<?php

declare(strict_types=1);

namespace Zitadel\Sdk\Bridge\Phalcon;

use Phalcon\Di\DiInterface;
use Phalcon\Di\ServiceProviderInterface;
use Zitadel\Sdk\Auth\JwksCache;
use Zitadel\Sdk\Auth\TokenValidator;
use Zitadel\Sdk\Config\ZitadelConfig;

/**
 * Registers all Zitadel SDK services in the Phalcon DI container.
 *
 * Implements {@see ServiceProviderInterface} so it can be used with the standard
 * Phalcon DI provider pattern:
 *
 * ```php
 * $di->register(new ZitadelServiceProvider($config));
 * ```
 *
 * A static convenience method {@see create()} is also provided as an alternative
 * one-liner that avoids the `new` keyword:
 *
 * ```php
 * ZitadelServiceProvider::create($di, $config);
 * ```
 *
 * After registration the plugin is available via `$di->get('zitadelPlugin')` and
 * can be attached to any events manager:
 *
 * ```php
 * $plugin = $di->get('zitadelPlugin');
 * $eventsManager->attach('application', $plugin);
 * $eventsManager->attach('dispatch',    $plugin);
 * ```
 *
 * Registered services:
 * - `zitadelConfig`    — the {@see ZitadelConfig} instance passed to the constructor
 * - `zitadelValidator` — a shared {@see TokenValidator} backed by a {@see JwksCache}
 * - `zitadelPlugin`    — a shared {@see ZitadelPlugin} wired to the config and validator
 */
final readonly class ZitadelServiceProvider implements ServiceProviderInterface
{
    public function __construct(private ZitadelConfig $config)
    {
    }

    /**
     * Registers Zitadel SDK services as shared bindings in the DI container.
     *
     * @param DiInterface $di The Phalcon DI container to register services into.
     */
    #[\Override]
    public function register(DiInterface $di): void
    {
        $config = $this->config;

        $di->setShared('zitadelConfig', $config);

        $di->setShared('zitadelValidator', fn () => new TokenValidator($config, new JwksCache()));

        $di->setShared('zitadelPlugin', fn () => new ZitadelPlugin($config, $di->get('zitadelValidator')));
    }

    /**
     * Convenience static method — registers Zitadel services without instantiating
     * the provider manually. Equivalent to `$di->register(new self($config))`.
     *
     * ```php
     * ZitadelServiceProvider::create($di, ZitadelConfig::fromArray([...]));
     * ```
     *
     * @param DiInterface   $di     The Phalcon DI container to register services into.
     * @param ZitadelConfig $config The SDK configuration for this application.
     */
    public static function create(DiInterface $di, ZitadelConfig $config): void
    {
        (new self($config))->register($di);
    }
}
