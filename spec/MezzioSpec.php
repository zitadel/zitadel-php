<?php

declare(strict_types=1);

namespace Zitadel\Sdk\Spec;

use PHPUnit\Framework\Attributes\Group;

/**
 * Integration spec for the Mezzio bridge (generic PSR-15 ZitadelMiddleware).
 *
 * The fixture app lives at `spec/fixtures/mezzio/` and runs on port 9007.
 * Routing uses `mezzio/mezzio-fastroute`; the RouteResult attribute is pre-set
 * on the request before ZitadelMiddleware runs, enabling #[AllowAnonymous]
 * reflection at step 6a for Mezzio-aware deployments.
 */
#[Group('integration')]
final class MezzioSpec extends AbstractIntegrationSpec
{
    #[\Override]
    protected static function fixtureDir(): string
    {
        return __DIR__ . '/fixtures/mezzio';
    }

    #[\Override]
    protected static function fixturePort(): int
    {
        return 9007;
    }

    /** The generic PSR-15 middleware has no event dispatcher wired — skip. */
    #[\Override]
    public function testLoginEventIsDispatched(): void
    {
        $this->markTestSkipped('Generic PSR-15 ZitadelMiddleware does not dispatch framework events.');
    }

    /** The generic PSR-15 middleware has no event dispatcher wired — skip. */
    #[\Override]
    public function testLogoutEventIsDispatched(): void
    {
        $this->markTestSkipped('Generic PSR-15 ZitadelMiddleware does not dispatch framework events.');
    }
}
