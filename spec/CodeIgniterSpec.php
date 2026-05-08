<?php

declare(strict_types=1);

namespace Zitadel\Sdk\Spec;

/**
 * Integration spec for the CodeIgniter 4 bridge.
 *
 * The fixture app lives at `spec/fixtures/codeigniter/` and runs on port 9004.
 *
 * @group integration
 */
final class CodeIgniterSpec extends AbstractIntegrationSpec
{
    #[\Override]
    protected function baseUrl(): string
    {
        return 'http://localhost:' . $this->port();
    }

    #[\Override]
    protected function port(): int
    {
        return 9004;
    }
}
