<?php

declare(strict_types=1);

namespace Zitadel\Sdk\Bridge\Symfony;

use Symfony\Component\HttpKernel\Bundle\Bundle;
use Zitadel\Sdk\Bridge\Symfony\DependencyInjection\ZitadelExtension;

/**
 * Symfony bundle for the Zitadel SDK.
 *
 * Register in `config/bundles.php`:
 * ```php
 * Zitadel\Sdk\Bridge\Symfony\ZitadelBundle::class => ['all' => true],
 * ```
 *
 * Configure via `config/packages/zitadel.yaml`.
 */
final class ZitadelBundle extends Bundle
{
    /**
     * Returns the DI extension that processes `config/packages/zitadel.yaml`.
     *
     * @return ZitadelExtension The bundle's dependency-injection extension.
     */
    #[\Override]
    public function getContainerExtension(): ZitadelExtension
    {
        return new ZitadelExtension();
    }
}
