<?php

declare(strict_types=1);

namespace Zitadel\Sdk\Bridge\CodeIgniter\Commands;

use CodeIgniter\CLI\BaseCommand;
use CodeIgniter\CLI\CLI;

/**
 * Generates a cryptographically secure random 64-character hex string for use as
 * the `ZITADEL_COOKIE_SECRET` environment variable.
 *
 * Usage:
 * ```bash
 * php spark zitadel:generate-secret
 * ```
 *
 * Copy the output directly into your `.env` file:
 * ```
 * ZITADEL_COOKIE_SECRET=<output>
 * ```
 */
final class ZitadelGenerateSecret extends BaseCommand
{
    /** @var string */
    protected $group = 'Zitadel';

    /** @var string */
    protected $name = 'zitadel:generate-secret';

    /** @var string */
    protected $description = 'Generates a random 64-character hex string for ZITADEL_COOKIE_SECRET';

    /** @var string */
    protected $usage = 'zitadel:generate-secret';

    public function run(array $params): void
    {
        CLI::write(bin2hex(random_bytes(32)), 'green');
    }
}
