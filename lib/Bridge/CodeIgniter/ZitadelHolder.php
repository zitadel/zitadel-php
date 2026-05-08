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
 * **Long-running runtimes** (Swoole, RoadRunner): reset `$current` manually
 * between requests by calling `ZitadelHolder::set(null)` in your before-request
 * hook, or it will carry the previous request's claims.
 */
final class ZitadelHolder
{
    private static ?Claims $current = null;

    private function __construct() {}

    /**
     * Sets the claims for the current request. Called only by {@see ZitadelFilter}.
     */
    public static function set(?Claims $claims): void
    {
        self::$current = $claims;
    }

    /**
     * Returns the validated claims for the current request, or null if unauthenticated.
     */
    public static function claims(): ?Claims
    {
        return self::$current;
    }
}
