<?php

declare(strict_types=1);

namespace Config;

use Zitadel\Sdk\Bridge\CodeIgniter\Config\Zitadel as BaseZitadel;

/**
 * Application-specific Zitadel configuration.
 *
 * Credentials and endpoint overrides are read automatically from `.env` by the
 * base class. Override `$protectAll` and `$ignoredRoutes` here to suit the
 * application's access-control requirements.
 */
class Zitadel extends BaseZitadel
{
    public bool  $protectAll    = true;
    public array $ignoredRoutes = ['/health'];
}
