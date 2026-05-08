<?php

declare(strict_types=1);

namespace Zitadel\Sdk\Spec;

/**
 * Integration spec for the Yii 3 bridge.
 *
 * The fixture app lives at `spec/fixtures/yii/` and runs on port 9003.
 *
 * @group integration
 */
final class YiiSpec extends AbstractIntegrationSpec
{
    #[\Override]
    protected function baseUrl(): string
    {
        return 'http://localhost:' . $this->port();
    }

    #[\Override]
    protected function port(): int
    {
        return 9003;
    }
}
