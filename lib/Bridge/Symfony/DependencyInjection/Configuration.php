<?php

declare(strict_types=1);

namespace Zitadel\Sdk\Bridge\Symfony\DependencyInjection;

use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;

/**
 * Defines and validates the `zitadel` configuration tree.
 *
 * See `config/packages/zitadel.yaml` in the fixture app for a full example.
 */
readonly class Configuration implements ConfigurationInterface
{
    #[\Override]
    public function getConfigTreeBuilder(): TreeBuilder
    {
        $treeBuilder = new TreeBuilder('zitadel');
        $rootNode    = $treeBuilder->getRootNode();

        $rootNode
            ->children()
                ->scalarNode('issuer_url')->isRequired()->cannotBeEmpty()->end()
                ->scalarNode('client_id')->isRequired()->cannotBeEmpty()->end()
                ->scalarNode('redirect_uri')->isRequired()->cannotBeEmpty()->end()
                ->scalarNode('cookie_secret')->isRequired()->cannotBeEmpty()->end()
                ->scalarNode('callback_path')->defaultValue('/zitadel/callback')->end()
                ->scalarNode('logout_path')->defaultValue('/zitadel/logout')->end()
                ->scalarNode('post_login_redirect')->defaultValue('/')->end()
                ->scalarNode('post_logout_redirect')->defaultValue('/')->end()
                ->booleanNode('protect_all')->defaultFalse()->end()
                ->arrayNode('protected_routes')
                    ->scalarPrototype()->end()
                    ->defaultValue([])
                ->end()
                ->arrayNode('ignored_routes')
                    ->scalarPrototype()->end()
                    ->defaultValue([])
                ->end()
                ->arrayNode('scopes')
                    ->scalarPrototype()->end()
                    ->defaultValue(['openid', 'profile', 'email'])
                ->end()
                ->arrayNode('allowed_algorithms')
                    ->scalarPrototype()->end()
                    ->defaultValue(['RS256', 'ES256'])
                ->end()
                ->arrayNode('allowed_token_types')
                    ->scalarPrototype()->end()
                    ->defaultValue(['JWT', 'at+JWT'])
                ->end()
                ->variableNode('audience')->defaultNull()->end()
                ->integerNode('clock_skew_seconds')->defaultValue(5)->end()
                ->integerNode('jwks_ttl_seconds')->defaultValue(300)->end()
                ->integerNode('http_timeout_seconds')->defaultValue(5)->end()
            ->end();

        return $treeBuilder;
    }
}
