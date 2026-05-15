<?php

declare(strict_types=1);

namespace Zitadel\Sdk\Bridge\Laravel\Http\Controllers;

use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response as SymfonyResponse;
use Zitadel\Sdk\Auth\HttpProxy;
use Zitadel\Sdk\Config\ZitadelConfig;

/**
 * Invokable controller that reverse-proxies `/__nextgen/*` requests to the
 * upstream Zitadel auth backend.
 *
 * Strips hop-by-hop and internal headers in both directions, appends
 * `REMOTE_ADDR` to the `X-Forwarded-For` chain, and upgrades `__nextgen*`
 * session cookies to `Secure` when the client connection is HTTPS.
 *
 * Registered automatically by {@see \Zitadel\Sdk\Bridge\Laravel\ZitadelServiceProvider}
 * via `lib/Bridge/Laravel/routes/zitadel.php`. No manual route registration is needed.
 */
readonly class ProxyController
{
    /**
     * @param ZitadelConfig $config SDK configuration (issuer URL, proxy path, timeouts).
     */
    public function __construct(
        private ZitadelConfig $config,
    ) {
    }

    /**
     * Handles an incoming proxy request.
     *
     * Forwards the request to the upstream auth backend and returns the response
     * verbatim, with hop-by-hop headers stripped and `__nextgen*` session cookies
     * upgraded to `Secure` on HTTPS connections. Returns 502 Bad Gateway on failure.
     *
     * @param Request $request The incoming HTTP request.
     * @return SymfonyResponse The proxied upstream response (or 502 on failure).
     */
    public function __invoke(Request $request): SymfonyResponse
    {
        $proxyPath = rtrim($this->config->proxyPath, '/');
        $suffix    = substr($request->getPathInfo(), strlen($proxyPath));
        $query     = $request->getQueryString();
        $target    = $this->config->issuerUrl . $suffix . ($query !== null && $query !== '' ? '?' . $query : '');

        $headers = [];
        foreach ($request->headers->all() as $name => $values) {
            $headers[$name] = implode(', ', $values);
        }

        $method     = $request->getMethod();
        $hasBody    = !in_array(strtoupper($method), ['GET', 'HEAD'], true);
        $body       = $hasBody ? (string) $request->getContent() : '';
        $remoteAddr = (string) ($request->server->get('REMOTE_ADDR') ?? '');
        $host       = (string) ($request->headers->get('Host') ?: $request->getHost());
        $proto      = $request->getScheme();
        // Mirror Next.js/Nuxt behavior: consider X-Forwarded-Proto so that session
        // cookies get the Secure flag even when TLS is terminated at a load balancer.
        $isSecure   = $request->isSecure()
            || strtolower((string) ($request->headers->get('X-Forwarded-Proto') ?? '')) === 'https';

        try {
            $result = HttpProxy::forward(
                $method,
                $target,
                $headers,
                $body,
                $remoteAddr,
                $host,
                $proto,
                $this->config->httpTimeoutSeconds,
            );
        } catch (\RuntimeException) {
            return new SymfonyResponse('Bad Gateway', 502, ['Content-Type' => 'text/plain; charset=utf-8']);
        }

        $response = new SymfonyResponse($result['body'], $result['status']);

        foreach ($result['headers'] as $name => $values) {
            foreach ($values as $value) {
                $response->headers->set($name, $value, false);
            }
        }

        foreach ($result['setCookies'] as $cookie) {
            $response->headers->set(
                'Set-Cookie',
                HttpProxy::upgradeSessionCookie($cookie, $isSecure),
                false,
            );
        }

        return $response;
    }
}
