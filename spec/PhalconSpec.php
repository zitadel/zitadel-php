<?php

declare(strict_types=1);

namespace Zitadel\Sdk\Spec;

/**
 * Integration spec for the Phalcon bridge.
 *
 * The fixture app lives at `spec/fixtures/phalcon/` and runs on port 9005.
 *
 * @group integration
 */
final class PhalconSpec extends AbstractIntegrationSpec
{
    #[\Override]
    protected function baseUrl(): string
    {
        return 'http://localhost:' . $this->port();
    }

    #[\Override]
    protected function port(): int
    {
        return 9005;
    }
}
