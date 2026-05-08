<?php

declare(strict_types=1);

namespace Zitadel\Sdk\Bridge\Symfony\DependencyInjection;

use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Extension\Extension;
use Symfony\Component\DependencyInjection\Reference;
use Zitadel\Sdk\Auth\Algorithm;
use Zitadel\Sdk\Auth\JwksCache;
use Zitadel\Sdk\Auth\TokenType;
use Zitadel\Sdk\Auth\TokenValidator;
use Zitadel\Sdk\Bridge\Symfony\ArgumentResolver\ClaimsValueResolver;
use Zitadel\Sdk\Bridge\Symfony\EventListener\ZitadelListener;
use Zitadel\Sdk\Config\ZitadelConfig;

/**
 * Loads the Zitadel bundle configuration and registers services.
 *
 * Registers:
 * - {@see ZitadelConfig} as a shared (singleton) service
 * - {@see JwksCache} as a shared service
 * - {@see TokenValidator} as a shared service
 * - {@see ZitadelListener} as a tagged event subscriber
 * - {@see ClaimsValueResolver} as a tagged value resolver
 */
final class ZitadelExtension extends Extension
{
    #[\Override]
    public function load(array $configs, ContainerBuilder $container): void
    {
        $configuration = new Configuration();
        $config        = $this->processConfiguration($configuration, $configs);

        $allowedAlgorithms = array_map(
            static fn (string $v) => Algorithm::from($v),
            $config['allowed_algorithms']
        );

        $allowedTokenTypes = array_map(
            static fn (string $v) => TokenType::from($v),
            $config['allowed_token_types']
        );

        $container->register(ZitadelConfig::class, ZitadelConfig::class)
            ->setShared(true)
            ->setArguments([
                $config['issuer_url'],
                $config['client_id'],
                $config['redirect_uri'],
                $config['cookie_secret'],
                $config['callback_path'],
                $config['logout_path'],
                $config['post_login_redirect'],
                $config['post_logout_redirect'],
                $config['protect_all'],
                $config['ignored_routes'],
                $config['protected_routes'],
                $config['scopes'],
                $allowedAlgorithms,
                $allowedTokenTypes,
                $config['audience'],
                $config['clock_skew_seconds'],
                $config['jwks_ttl_seconds'],
                $config['http_timeout_seconds'],
            ]);

        $container->register(JwksCache::class, JwksCache::class)
            ->setShared(true);

        $container->register(TokenValidator::class, TokenValidator::class)
            ->setShared(true)
            ->setArguments([
                new Reference(ZitadelConfig::class),
                new Reference(JwksCache::class),
            ]);

        $container->register(ZitadelListener::class, ZitadelListener::class)
            ->setShared(true)
            ->setArguments([
                new Reference(ZitadelConfig::class),
                new Reference(TokenValidator::class),
            ])
            ->addTag('kernel.event_subscriber');

        $container->register(ClaimsValueResolver::class, ClaimsValueResolver::class)
            ->setShared(true)
            ->addTag('controller.argument_value_resolver', ['priority' => 50]);
    }
}
