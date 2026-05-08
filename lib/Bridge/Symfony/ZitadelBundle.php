<?php

declare(strict_types=1);

namespace Zitadel\Sdk\Bridge\Symfony;

use Symfony\Component\DependencyInjection\ContainerBuilder;
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
    #[\Override]
    public function build(ContainerBuilder $container): void
    {
        parent::build($container);
    }

    #[\Override]
    public function getContainerExtension(): ZitadelExtension
    {
        return new ZitadelExtension();
    }
}
