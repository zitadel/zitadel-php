<?php

declare(strict_types=1);

namespace Zitadel\Sdk\Spec;

use PHPUnit\Runner\Extension\Extension;
use PHPUnit\Runner\Extension\Facade;
use PHPUnit\Runner\Extension\ParameterCollection;
use PHPUnit\TextUI\Configuration\Configuration;

/**
 * PHPUnit extension bootstrap for integration specs.
 *
 * Registered in `phpunit.xml` as a bootstrap extension for the `specs` suite.
 * Currently a no-op placeholder — integration specs use Testcontainers and
 * Playwright directly from test class setup methods.
 */
final class Setup implements Extension
{
    #[\Override]
    public function bootstrap(Configuration $configuration, Facade $facade, ParameterCollection $parameters): void
    {
        // No-op: integration specs set up their own containers in setUp().
    }
}
