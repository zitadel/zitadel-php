<?php

declare(strict_types=1);

namespace Zitadel\Sdk\Spec;

use PHPUnit\Framework\Attributes\Group;

/**
 * Integration spec for the Yii 3 bridge.
 *
 * The fixture app lives at `spec/fixtures/yii/` and runs on port 9003.
 */
#[Group('integration')]
final class YiiSpec extends AbstractIntegrationSpec
{
    #[\Override]
    protected static function fixtureDir(): string
    {
        return __DIR__ . '/fixtures/yii';
    }

    #[\Override]
    protected static function fixturePort(): int
    {
        return 9003;
    }
}
