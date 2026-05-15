<?php

declare(strict_types=1);

namespace Zitadel\Sdk\Bridge\CodeIgniter;

use CodeIgniter\HTTP\IncomingRequest;
use CodeIgniter\HTTP\RequestInterface;
use CodeIgniter\HTTP\ResponseInterface;
use Zitadel\Sdk\Auth\HttpProxy;

/**
 * Pre-routing CI4 filter that dispatches the SDK's own HTTP paths.
 *
 * Registered in `$required['before']` via {@see \Zitadel\Sdk\Config\Registrar},
 * this filter runs before CI4's router. It intercepts the three path groups that
 * the SDK owns — the reverse-proxy prefix, the PKCE callback, and the logout
 * endpoint — none of which appear in `app/Config/Routes.php`. Every other URI
 * returns `null` immediately so that routing and the post-routing auth filter
 * ({@see ZitadelFilter}) can proceed.
 *
 * Keeping dispatch and auth in separate, stateless classes avoids the instance-
 * reuse problem that arises when the same class is registered in both
 * `$required['before']` and `$globals['before']`: CI4's `Filters` service caches
 * filter instances by class name, so a single class would receive both calls per
 * request. Splitting the responsibility means each class is called exactly once per
 * request with no shared mutable state.
 *
 * This filter is completely stateless and safe for persistent PHP processes
 * (FrankenPHP worker mode, Swoole, RoadRunner).
 */
final class ZitadelPreFilter extends ZitadelFilter
{
    /**
     * Dispatches SDK-owned paths before CI4's router runs.
     *
     * Returns a {@see ResponseInterface} for proxy, callback, and logout paths so
     * that CI4 short-circuits routing entirely. Returns `null` for everything else.
     *
     * @param RequestInterface  $request   The incoming HTTP request.
     * @param array<mixed>|null $arguments Unused — CI4 does not pass arguments to required filters.
     * @return ResponseInterface|null Response to short-circuit, or null to continue.
     */
    #[\Override]
    public function before(RequestInterface $request, $arguments = null): ?ResponseInterface
    {
        ZitadelHolder::set(null);

        if (!$request instanceof IncomingRequest) {
            return null;
        }

        $path = '/' . ltrim($request->getPath(), '/');

        if (HttpProxy::isProxyPath($path, $this->config->proxyPath)) {
            return $this->handleProxy($request);
        }
        if ($path === $this->config->callbackPath) {
            return $this->handleCallback($request);
        }
        if ($path === $this->config->logoutPath) {
            return $this->handleLogout($request);
        }

        return null;
    }
}
