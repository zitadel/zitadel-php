<?php

declare(strict_types=1);

namespace App\Filters;

use CodeIgniter\Filters\FilterInterface;
use CodeIgniter\HTTP\RequestInterface;
use CodeIgniter\HTTP\ResponseInterface;
use Config\Services;
use Zitadel\Sdk\Bridge\CodeIgniter\ZitadelFilter;

/**
 * Thin wrapper around ZitadelFilter that satisfies CI4's no-arg filter instantiation.
 *
 * CI4 creates filters via `new ClassName()` without dependency injection. This
 * wrapper reads dependencies from the Services container at construction time
 * and delegates all calls to the properly-constructed ZitadelFilter.
 */
final class ZitadelFilterWrapper implements FilterInterface
{
    private readonly ZitadelFilter $inner;

    public function __construct()
    {
        $config      = Services::zitadelConfig(false);
        $validator   = Services::zitadelValidator(false);
        $this->inner = new ZitadelFilter($config, $validator);
    }

    #[\Override]
    public function before(RequestInterface $request, $arguments = null): ?ResponseInterface
    {
        return $this->inner->before($request, $arguments);
    }

    #[\Override]
    public function after(RequestInterface $request, ResponseInterface $response, $arguments = null): ResponseInterface
    {
        return $this->inner->after($request, $response, $arguments);
    }
}
