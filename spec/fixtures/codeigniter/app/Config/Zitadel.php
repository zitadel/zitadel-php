<?php

declare(strict_types=1);

namespace Config;

use Zitadel\Sdk\Bridge\CodeIgniter\Config\Zitadel as BaseZitadel;

/**
 * Zitadel SDK configuration for the integration spec fixture.
 *
 * All settings are injected via the .env file written by AbstractIntegrationSpec
 * before the PHP built-in server starts. No properties need to be overridden here.
 */
class Zitadel extends BaseZitadel {}
