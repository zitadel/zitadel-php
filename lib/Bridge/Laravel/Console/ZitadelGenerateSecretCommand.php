<?php

declare(strict_types=1);

namespace Zitadel\Sdk\Bridge\Laravel\Console;

use Illuminate\Console\Command;
use Symfony\Component\Console\Attribute\AsCommand;

/**
 * Artisan command that generates a cryptographically secure 64-character hex string
 * for use as the `ZITADEL_COOKIE_SECRET` environment variable.
 *
 * Usage:
 * ```bash
 * php artisan zitadel:generate-secret
 * ```
 *
 * Copy the output directly into your `.env` file:
 * ```
 * ZITADEL_COOKIE_SECRET=<output>
 * ```
 */
#[AsCommand(name: 'zitadel:generate-secret')]
final class ZitadelGenerateSecretCommand extends Command
{
    /** @var string */
    protected $signature = 'zitadel:generate-secret';

    /** @var string */
    protected $description = 'Generate a random ZITADEL_COOKIE_SECRET value (64-character hex string)';

    public function handle(): void
    {
        $this->line(bin2hex(random_bytes(32)));
    }
}
