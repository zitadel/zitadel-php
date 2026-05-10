<?php

declare(strict_types=1);

namespace Zitadel\Sdk\Spec;

use PHPUnit\Framework\Attributes\Group;

/**
 * Integration spec for the CodeIgniter 4 bridge.
 *
 * The fixture app lives at `spec/fixtures/codeigniter/` and runs on port 9004.
 */
#[Group('integration')]
final class CodeIgniterSpec extends AbstractIntegrationSpec
{
    #[\Override]
    protected static function fixtureDir(): string
    {
        return __DIR__ . '/fixtures/codeigniter';
    }

    #[\Override]
    protected static function fixturePort(): int
    {
        return 9004;
    }
}
