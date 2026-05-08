<?php

declare(strict_types=1);

namespace Zitadel\Sdk\Spec;

/**
 * Integration spec for the Symfony bridge.
 *
 * The fixture app lives at `spec/fixtures/symfony/` and runs on port 9002.
 *
 * @group integration
 */
final class SymfonySpec extends AbstractIntegrationSpec
{
    #[\Override]
    protected function baseUrl(): string
    {
        return 'http://localhost:' . $this->port();
    }

    #[\Override]
    protected function port(): int
    {
        return 9002;
    }
}
