<?php

declare(strict_types=1);

namespace Zitadel\Sdk\Bridge\Symfony\ArgumentResolver;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Controller\ValueResolverInterface;
use Symfony\Component\HttpKernel\ControllerMetadata\ArgumentMetadata;
use Zitadel\Sdk\Auth\Claims;

/**
 * Resolves `?Claims $claims` controller parameters from the request attributes.
 *
 * Auto-tagged as `controller.argument_value_resolver` by {@see ZitadelExtension}.
 * No manual service configuration is required.
 *
 * Usage in any Symfony controller:
 * ```php
 * public function index(?Claims $claims): Response
 * {
 *     return new Response("Hello {$claims?->name}");
 * }
 * ```
 *
 * The parameter must be typed as {@see Claims} or `?Claims`. Any other type is
 * ignored and resolved by other resolvers in the chain.
 */
readonly class ClaimsValueResolver implements ValueResolverInterface
{
    /**
     * @param Request          $request  The current HTTP request.
     * @param ArgumentMetadata $argument Metadata about the controller parameter being resolved.
     * @return iterable<Claims|null>
     */
    #[\Override]
    public function resolve(Request $request, ArgumentMetadata $argument): iterable
    {
        if ($argument->getType() !== Claims::class) {
            return;
        }

        yield $request->attributes->get('zitadel.claims');
    }
}
