<?php

declare(strict_types=1);

namespace Zitadel\Sdk\Bridge\Symfony\Command;

use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Symfony console command that generates a cryptographically secure 64-character hex
 * string for use as the `ZITADEL_COOKIE_SECRET` environment variable.
 *
 * Usage:
 * ```bash
 * php bin/console zitadel:generate-secret
 * ```
 *
 * Copy the output directly into your `.env` file:
 * ```
 * ZITADEL_COOKIE_SECRET=<output>
 * ```
 */
#[AsCommand(
    name: 'zitadel:generate-secret',
    description: 'Generate a random ZITADEL_COOKIE_SECRET value (64-character hex string)',
)]
final class ZitadelGenerateSecretCommand extends Command
{
    #[\Override]
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $output->writeln(bin2hex(random_bytes(32)));

        return Command::SUCCESS;
    }
}
