<?php

declare(strict_types=1);

namespace Zitadel\Sdk\Spec;

/**
 * Integration spec for the Laravel bridge.
 *
 * The fixture app lives at `spec/fixtures/laravel/` and runs on port 9001.
 * See `spec/fixtures/laravel/composer.json` and `.env.example` for setup.
 *
 * @group integration
 */
final class LaravelSpec extends AbstractIntegrationSpec
{
    #[\Override]
    protected function baseUrl(): string
    {
        return 'http://localhost:' . $this->port();
    }

    #[\Override]
    protected function port(): int
    {
        return 9001;
    }
}
