<?php

declare(strict_types=1);

namespace Zitadel\Sdk\Config;

use Zitadel\Sdk\Bridge\CodeIgniter\ZitadelFilter;
use Zitadel\Sdk\Bridge\CodeIgniter\ZitadelPreFilter;

/**
 * CodeIgniter 4 auto-discovery hook.
 *
 * CI4 scans every Composer PSR-4 root namespace for a `Config\Registrar` class and
 * merges each static method's return value into the matching Config class. Because the
 * SDK registers `Zitadel\Sdk` → `lib/` in its `composer.json` autoload, CI4 picks up
 * this class automatically when `Config\Modules::$discoverInComposer` is `true` (the
 * CI4 4.x default).
 *
 * Effect: `ZitadelFilter` is registered as a **required** `before` filter. Required
 * filters run before routing and are applied even when no route matches the URI — this
 * is what allows the filter to intercept the callback, logout, and proxy paths without
 * those paths needing an entry in `app/Config/Routes.php`.
 *
 * Returning only `required['before']` (no `required['after']`) is intentional: CI4's
 * `getRequiredFilters()` falls back to the system `CodeIgniter\Config\Filters` defaults
 * for any position that is not explicitly set in the application config, so the built-in
 * `pagecache`, `performance`, and `toolbar` after-filters continue to work unchanged.
 *
 * Every other framework ignores this file entirely — it imports no CI4 classes and is
 * never called outside a CI4 bootstrap.
 */
final class Registrar
{
    /**
     * Merges the Zitadel filter alias and required before-filter into `Config\Filters`.
     *
     * @return array{aliases: array<string, class-string>, required: array{before: string[]}}
     */
    public static function Filters(): array
    {
        return [
            'aliases'  => [
                'zitadel'     => ZitadelFilter::class,
                'zitadel_pre' => ZitadelPreFilter::class,
            ],
            'required' => ['before' => ['zitadel_pre']],
            'globals'  => ['before' => ['zitadel']],
        ];
    }
}
