<?php

declare(strict_types=1);

namespace Zitadel\Sdk\Spec;

use PHPUnit\Framework\Attributes\Group;

/**
 * Integration spec for the Symfony bridge.
 *
 * The fixture app lives at `spec/fixtures/symfony/` and runs on port 9002.
 */
#[Group('integration')]
final class SymfonySpec extends AbstractIntegrationSpec
{
    #[\Override]
    protected static function fixtureDir(): string
    {
        return __DIR__ . '/fixtures/symfony';
    }

    #[\Override]
    protected static function fixturePort(): int
    {
        return 9002;
    }
}
