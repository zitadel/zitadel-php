<?php

declare(strict_types=1);

namespace Zitadel\Sdk\Spec;

use PHPUnit\Framework\Attributes\Group;

/**
 * Integration spec for the Slim 4 bridge (generic PSR-15 ZitadelMiddleware).
 *
 * The fixture app lives at `spec/fixtures/slim/` and runs on port 9006.
 * Routes use `protectedRoutes: ['/dashboard']` with `protectAll: false` so
 * that `/home` and `/api` are accessible without authentication.
 */
#[Group('integration')]
final class SlimSpec extends AbstractIntegrationSpec
{
    #[\Override]
    protected static function fixtureDir(): string
    {
        return __DIR__ . '/fixtures/slim';
    }

    #[\Override]
    protected static function fixturePort(): int
    {
        return 9006;
    }
}
