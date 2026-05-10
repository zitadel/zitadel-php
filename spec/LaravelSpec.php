<?php

declare(strict_types=1);

namespace Zitadel\Sdk\Spec;

use PHPUnit\Framework\Attributes\Group;

/**
 * Integration spec for the Laravel bridge.
 *
 * The fixture app lives at `spec/fixtures/laravel/` and runs on port 9001.
 * See `spec/fixtures/laravel/composer.json` and `.env.example` for setup.
 */
#[Group('integration')]
final class LaravelSpec extends AbstractIntegrationSpec
{
    #[\Override]
    protected static function fixtureDir(): string
    {
        return __DIR__ . '/fixtures/laravel';
    }

    #[\Override]
    protected static function fixturePort(): int
    {
        return 9001;
    }
}
