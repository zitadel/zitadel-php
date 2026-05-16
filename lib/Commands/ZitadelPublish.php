<?php

declare(strict_types=1);

namespace Zitadel\Sdk\Commands;

use CodeIgniter\CLI\BaseCommand;
use CodeIgniter\CLI\CLI;

/**
 * Publishes a minimal Zitadel configuration stub to `app/Config/Zitadel.php`.
 *
 * Mirrors the pattern of `php spark shield:publish`: writes a thin subclass to
 * the application's Config directory so developers have a place to override
 * individual properties while reading everything else from environment variables.
 *
 * Usage:
 * ```bash
 * php spark zitadel:publish
 * ```
 *
 * The generated file is intentionally empty — no properties need to be set in
 * code because the base class reads all configuration from environment variables.
 * Add a public property only when you prefer to hard-code a value:
 *
 * ```php
 * public array $ignoredRoutes = ['/health', '/status'];
 * ```
 */
final class ZitadelPublish extends BaseCommand
{
    /** @var string */
    protected $group = 'Zitadel';

    /** @var string */
    protected $name = 'zitadel:publish';

    /** @var string */
    protected $description = 'Publishes the Zitadel config stub to app/Config/Zitadel.php';

    /** @var string */
    protected $usage = 'zitadel:publish';

    public function run(array $params): void
    {
        $destination = APPPATH . 'Config/Zitadel.php';

        if (is_file($destination)) {
            CLI::write('app/Config/Zitadel.php already exists — skipping.', 'yellow');

            return;
        }

        $content = <<<'PHP'
            <?php

            declare(strict_types=1);

            namespace Config;

            use Zitadel\Sdk\Bridge\CodeIgniter\Config\Zitadel as BaseZitadel;

            /**
             * Zitadel SDK configuration.
             *
             * All settings are read from environment variables by the base class — see
             * vendor/zitadel/sdk/lib/Bridge/CodeIgniter/Config/Zitadel.php for the full list.
             *
             * To override a setting in code instead of via .env, add a public property here:
             *
             *   public array $ignoredRoutes = ['/health', '/status'];
             */
            class Zitadel extends BaseZitadel {}
            PHP;

        // Dedent the heredoc (it is indented for readability above but must be flush in the file).
        $content = preg_replace('/^[ \t]{12}/m', '', $content) ?? $content;

        file_put_contents($destination, $content . "\n");

        CLI::write('Published: app/Config/Zitadel.php', 'green');
        CLI::newLine();
        CLI::write('Add the following to your .env file:', 'white');
        CLI::write('  ZITADEL_ISSUER_URL=https://your-domain.zitadel.cloud', 'white');
        CLI::write('  ZITADEL_CLIENT_ID=your-client-id', 'white');
        CLI::write('  ZITADEL_COOKIE_SECRET=your-64-char-hex-secret   # bin2hex(random_bytes(32))', 'white');
        CLI::write('  SERVER_URL=https://your-app.com                  # used to derive redirect URI', 'white');
        CLI::write('  ZITADEL_PROTECT_ALL=true                         # require auth on all routes', 'white');
    }
}
