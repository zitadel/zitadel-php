<?php

declare(strict_types=1);

use Zitadel\Sdk\Auth\Claims;
use Zitadel\Sdk\Bridge\CodeIgniter\ZitadelHolder;

/**
 * Returns the validated JWT claims for the current CodeIgniter 4 request.
 *
 * Shorthand for {@see ZitadelHolder::claims()}, modelled after CI4 Shield's
 * `auth()->user()` pattern. Available automatically in all CI4 controllers
 * and views after the SDK is installed — no `use` import required.
 *
 * @return Claims|null Authenticated claims, or null when unauthenticated.
 */
if (!function_exists('zitadel_claims')) {
    function zitadel_claims(): ?Claims
    {
        return ZitadelHolder::claims();
    }
}
