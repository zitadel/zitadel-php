<?php

declare(strict_types=1);

namespace Zitadel\Sdk\Spec;

use PHPUnit\Framework\Attributes\Group;

/**
 * Integration spec for the Phalcon bridge.
 *
 * The fixture app lives at `spec/fixtures/phalcon/` and runs on port 9005.
 */
#[Group('integration')]
final class PhalconSpec extends AbstractIntegrationSpec
{
    #[\Override]
    protected static function fixtureDir(): string
    {
        return __DIR__ . '/fixtures/phalcon';
    }

    #[\Override]
    protected static function fixturePort(): int
    {
        return 9005;
    }
}
