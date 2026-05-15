<?php

declare(strict_types=1);

namespace Zitadel\Sdk\Bridge\CodeIgniter;

use Zitadel\Sdk\Auth\Claims;

/**
 * Per-request static holder for the authenticated {@see Claims}.
 *
 * This is the **second** class in the library with mutable state. CI4's filter
 * architecture has no request-attribute system; a static holder is the only
 * alternative to server-side sessions for passing claims from a `FilterInterface`
 * to a controller within the same PHP process lifecycle.
 *
 * Set by {@see ZitadelFilter::before()} after successful token validation.
 * Read by controllers via {@see claims()}.
 *
 * **Long-running runtimes** (Swoole, RoadRunner): {@see ZitadelFilter::before()}
 * already resets `$current` to null at the start of every request, so no manual
 * reset is needed when the filter is active. If you bypass the filter (e.g. in CLI
 * commands or custom test setups), call `ZitadelHolder::set(null)` explicitly to
 * prevent claim leakage between logical requests.
 */
final class ZitadelHolder
{
    private static ?Claims $current = null;

    private function __construct()
    {
    }

    /**
     * Sets the claims for the current request. Called only by {@see ZitadelFilter}.
     *
     * @param Claims|null $claims Validated JWT claims, or null for unauthenticated requests.
     */
    public static function set(?Claims $claims): void
    {
        self::$current = $claims;
    }

    /**
     * Returns the validated claims for the current request, or null if unauthenticated.
     *
     * @return Claims|null Authenticated claims, or null when no valid session exists.
     */
    public static function claims(): ?Claims
    {
        return self::$current;
    }
}
