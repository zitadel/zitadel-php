<?php

declare(strict_types=1);

namespace Config;

use CodeIgniter\Config\BaseConfig;
use Zitadel\Sdk\Bridge\CodeIgniter\ZitadelFilter;
use Zitadel\Sdk\Bridge\CodeIgniter\ZitadelPreFilter;

/**
 * ZitadelFilter is registered here as a required before-filter.
 *
 * Required filters (Config\Filters::$required) run before routing and are
 * applied even when no route matches the URI. This is necessary for the SDK
 * to intercept the callback, logout, and proxy paths without those paths
 * needing entries in app/Config/Routes.php.
 *
 * When the SDK is installed as a real Composer package, CI4's Composer module
 * discovery picks up {@see \Zitadel\Sdk\Config\Registrar} automatically and
 * registers the filter without this file needing to be changed. For path-
 * repository setups (e.g. during SDK development) and for maximum
 * compatibility, keep the entries below.
 *
 * Only $required['before'] is overridden here. CI4 falls back to the system
 * CodeIgniter\Config\Filters defaults for $required['after'], so the built-in
 * pagecache, performance, and toolbar filters continue to work unchanged.
 */
class Filters extends BaseConfig
{
    /** @var array<string, class-string> */
    public array $aliases = [
        'zitadel'     => ZitadelFilter::class,
        'zitadel_pre' => ZitadelPreFilter::class,
    ];

    /**
     * Required filters run before routing, even for URIs with no matching route.
     *
     * @var array{before: list<string>}
     */
    public array $required = [
        'before' => ['zitadel_pre'],
    ];

    /** @var array<string, list<string>> */
    public array $globals = [
        'before' => ['zitadel'],
        'after'  => [],
    ];

    /** @var array<string, list<string>> */
    public array $methods = [];

    /** @var array<string, list<string>> */
    public array $filters = [];
}
