<?php

declare(strict_types=1);

namespace Zitadel\Sdk\Auth;

/**
 * Static helper for reverse-proxying requests to the upstream auth backend.
 *
 * Strips hop-by-hop and SDK-internal headers in both directions, appends the
 * direct client IP to the X-Forwarded-For chain, and upgrades `__nextgen*`
 * session cookies to `Secure` when the client-facing connection is HTTPS.
 *
 * This is a PHP port of the `proxyRequest()` function shared by the Next.js
 * edge middleware (`sdk-next`) and the Nuxt server middleware (`sdk-nuxt`).
 */
final class HttpProxy
{
    /**
     * Headers that must never be forwarded to an upstream service.
     *
     * These are connection-level headers that are meaningful only between two
     * directly connected peers and become invalid when proxied.
     *
     * `host` is not a hop-by-hop header per RFC 7230, but must be stripped so
     * cURL derives the correct `Host` from the upstream URL rather than
     * forwarding the client's `Host` and causing SNI/vhost mismatches.
     *
     * @var list<string>
     */
    private const HOP_BY_HOP = [
        'connection',
        'host',
        'keep-alive',
        'proxy-authenticate',
        'proxy-authorization',
        'te',
        'trailer',
        'transfer-encoding',
        'upgrade',
    ];

    /**
     * SDK-internal headers that must never be forwarded to the upstream backend.
     *
     * These headers carry session data between the middleware and server
     * components; forwarding them upstream would expose internal state and allow
     * header injection.
     *
     * @var list<string>
     */
    private const INTERNAL_HEADERS = [
        'x-nextgen-auth-token',
        'cookie', // Never forward session cookies to the upstream auth backend
    ];

    /**
     * Maximum allowed size (bytes) of the request body forwarded to the upstream.
     * Requests to the proxy path are JWKS/token exchanges that never have large bodies;
     * an oversized body is a strong signal of a DoS attempt and is rejected early.
     */
    private const int MAX_REQUEST_BODY_BYTES = 1_048_576; // 1 MB

    /**
     * Maximum allowed size (bytes) of the response body returned by the upstream.
     * JWKS and token-exchange responses are typically < 10 KB; capping at 1 MB
     * prevents a malicious or misconfigured upstream from exhausting PHP worker memory
     * in long-running runtimes (FrankenPHP, RoadRunner, Swoole).
     */
    private const int MAX_RESPONSE_BODY_BYTES = 1_048_576; // 1 MB

    private function __construct()
    {
    }

    /**
     * Returns true when `$path` matches the configured proxy prefix.
     *
     * Matches exactly `$proxyPath` or any path that starts with `$proxyPath/`
     * to avoid matching paths that merely share the same prefix characters
     * (e.g. `/__nextgenother` must not match `/__nextgen`).
     *
     * @param string $path      The request path (e.g. `'/__nextgen/oauth/v2/keys'`).
     * @param string $proxyPath The configured proxy path prefix (e.g. `'/__nextgen'`).
     * @return bool True when `$path` should be forwarded to the upstream backend.
     */
    public static function isProxyPath(string $path, string $proxyPath): bool
    {
        $prefix = rtrim($proxyPath, '/');

        return $path === $prefix || str_starts_with($path, $prefix . '/');
    }

    /**
     * Conditionally adds the `Secure` flag to any cookie set by the upstream.
     *
     * The proxy may terminate TLS — the upstream auth server cannot know whether
     * the browser-facing connection is HTTPS. When `$secure` is `true` (i.e. the
     * original request arrived over HTTPS), `Secure` is appended to every cookie
     * so that session and CSRF cookies set by the OIDC server are never sent over
     * plain HTTP on subsequent requests. This covers both SDK-named `__nextgen*`
     * cookies and any other cookies the OIDC server may set (e.g. CSRF tokens,
     * state cookies). When `$secure` is `false` (plain HTTP), the flag is
     * intentionally omitted: browsers refuse to store cookies with `Secure` on
     * non-TLS connections, which would break the auth flow entirely.
     *
     * @param string $cookie Raw `Set-Cookie` header value.
     * @param bool   $secure `true` when the client-facing connection is HTTPS.
     * @return string The (possibly upgraded) `Set-Cookie` value.
     */
    public static function upgradeSessionCookie(string $cookie, bool $secure): string
    {
        if (!$secure) {
            return $cookie;
        }

        // Case-insensitive check to avoid doubling an existing Secure flag.
        if (preg_match('/;\s*Secure\b/i', $cookie) === 1) {
            return $cookie;
        }

        return $cookie . '; Secure';
    }

    /**
     * Forwards an incoming request to the upstream auth backend and returns
     * the raw response data.
     *
     * Strips hop-by-hop and internal headers in both directions. Always appends
     * `$remoteAddr` to the `X-Forwarded-For` chain (even when a chain already
     * exists from an upstream CDN) so the auth server sees the full proxy path.
     * Sets `X-Forwarded-Host` and `X-Forwarded-Proto` only when absent,
     * preserving values injected by an upstream CDN or load balancer. Strips
     * `location` from the response — this is a pure API proxy that never issues
     * redirects. Returns `Set-Cookie` values separately so callers can apply
     * {@see upgradeSessionCookie()} per cookie before emitting them.
     *
     * @param string               $method         HTTP method (e.g. `'GET'`, `'POST'`).
     * @param string               $targetUrl      Full upstream URL to forward to.
     * @param array<string,string> $requestHeaders Incoming request headers (name → value).
     * @param string               $body           Request body (empty string for GET/HEAD).
     * @param string               $remoteAddr     Direct client IP to append to X-Forwarded-For.
     * @param string               $host           Client-facing Host header for X-Forwarded-Host.
     * @param string               $proto          Client-facing scheme for X-Forwarded-Proto.
     * @param int                  $timeoutSeconds cURL timeout in seconds.
     * @return array{status: int, headers: array<string, list<string>>, setCookies: list<string>, body: string}
     * @throws \RuntimeException On cURL initialisation or network failure.
     */
    public static function forward(
        string $method,
        string $targetUrl,
        array  $requestHeaders,
        string $body,
        string $remoteAddr,
        string $host,
        string $proto,
        int    $timeoutSeconds = 5,
    ): array {
        $hopByHop = array_flip(self::HOP_BY_HOP);
        $internal = array_flip(self::INTERNAL_HEADERS);

        $upstreamHeaders = [];
        $existingXff     = null;
        $hasXfh          = false;
        $hasXfp          = false;

        foreach ($requestHeaders as $name => $value) {
            $lower = strtolower($name);

            // Let cURL compute Content-Length from the POSTFIELDS body so we
            // never send a stale or mismatched value from the original request.
            if ($lower === 'content-length') {
                continue;
            }

            if (isset($hopByHop[$lower]) || isset($internal[$lower])) {
                continue;
            }

            // Reject headers whose values contain CR or LF to prevent CRLF injection
            // into the upstream request. cURL 7.77+ blocks these automatically, but
            // we validate explicitly so behaviour is not cURL-version-dependent.
            if (str_contains($value, "\r") || str_contains($value, "\n")) {
                continue;
            }

            if ($lower === 'x-forwarded-for') {
                $existingXff = $value;
                continue; // Rebuilt below with $remoteAddr appended
            }

            if ($lower === 'x-forwarded-host') {
                $hasXfh = true;
            }

            if ($lower === 'x-forwarded-proto') {
                $hasXfp = true;
            }

            $upstreamHeaders[$name] = $value;
        }

        // Always append the direct client IP to the X-Forwarded-For chain so
        // the upstream auth server sees the full proxy path. We never skip this
        // even when a chain is already present — a CDN or load balancer may have
        // set XFF before the request reached this server, and our hop must still
        // be recorded.
        if ($remoteAddr !== '') {
            $upstreamHeaders['X-Forwarded-For'] = $existingXff !== null
                ? $existingXff . ', ' . $remoteAddr
                : $remoteAddr;
        } elseif ($existingXff !== null) {
            $upstreamHeaders['X-Forwarded-For'] = $existingXff;
        }

        if (!$hasXfh && $host !== '') {
            $upstreamHeaders['X-Forwarded-Host'] = $host;
        }

        if (!$hasXfp && $proto !== '') {
            $upstreamHeaders['X-Forwarded-Proto'] = $proto;
        }

        $curlHeaders = [];
        foreach ($upstreamHeaders as $name => $value) {
            $curlHeaders[] = $name . ': ' . $value;
        }

        // curl_init() in PHP 8 throws a ValueError (an Error, not an Exception) when
        // the URL contains a null byte, because libcurl treats URLs as C strings and
        // stops at the first null byte. Catching ValueError from curl_init() would mask
        // a real programming error, so we validate proactively and throw a RuntimeException
        // so the middleware's catch block can convert it to a 502 instead of an unhandled
        // exception that crashes with a 500.
        if (str_contains($targetUrl, "\0")) {
            throw new \RuntimeException('[zitadel] Proxy target URL contains a null byte.');
        }

        $ch = curl_init($targetUrl);
        if ($ch === false) {
            throw new \RuntimeException('[zitadel] Failed to initialise cURL for proxy request.');
        }

        $hasBody = !in_array(strtoupper($method), ['GET', 'HEAD'], true);

        if ($hasBody && strlen($body) > self::MAX_REQUEST_BODY_BYTES) {
            throw new \RuntimeException('[zitadel] Proxy request body exceeds the 1 MB limit.');
        }

        $opts = [
            CURLOPT_CUSTOMREQUEST  => strtoupper($method),
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADER         => true,
            CURLOPT_FOLLOWLOCATION => false, // Never follow redirects — strip location header
            CURLOPT_TIMEOUT        => $timeoutSeconds,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_MAXFILESIZE    => self::MAX_RESPONSE_BODY_BYTES,
            CURLOPT_HTTPHEADER     => $curlHeaders,
        ];

        // Always set POSTFIELDS for non-GET/HEAD methods — even an empty string —
        // so that DELETE/POST with no payload sends Content-Length: 0, matching
        // the Fetch API's behaviour (fetch() sends an empty body rather than
        // omitting it when the method is non-GET/HEAD).
        if ($hasBody) {
            $opts[CURLOPT_POSTFIELDS] = $body;
        }

        curl_setopt_array($ch, $opts);

        $raw   = curl_exec($ch);
        $errno = curl_errno($ch);
        $error = curl_error($ch);

        if ($errno !== 0 || $raw === false) {
            // curl_close() is a no-op since PHP 8.0 — the handle is freed when
            // it goes out of scope. Calling it explicitly triggers a deprecation
            // notice in PHP 8.5+ which can interfere with phpunit's error handler
            // when invoked outside a test method context (e.g. setUpBeforeClass).
            throw new \RuntimeException("[zitadel] Proxy request failed: {$error} (errno {$errno})");
        }

        /** @var string $raw */
        $headerSize = (int) curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        $status     = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);

        $rawHeaders   = substr($raw, 0, $headerSize);
        $responseBody = substr($raw, $headerSize);

        // Response headers to strip: all hop-by-hop headers, plus `location`
        // (this proxy never issues redirects, so leaking internal upstream URLs
        // to the browser is both unnecessary and potentially misleading), plus
        // SDK-internal headers (a compromised or misconfigured upstream must not
        // be able to plant an `x-nextgen-auth-token` value that reaches the
        // browser and is later re-sent as if it were a legitimate SDK token).
        $responseHopByHop = array_flip([...self::HOP_BY_HOP, 'location', ...self::INTERNAL_HEADERS]);
        $responseHeaders  = [];
        $setCookies       = [];

        foreach (explode("\r\n", $rawHeaders) as $line) {
            if (!str_contains($line, ':')) {
                continue; // Skip the HTTP status line and blank lines
            }

            [$rawName, $rawValue] = explode(':', $line, 2);
            $rawName  = trim($rawName);
            $rawValue = trim($rawValue);
            $lower    = strtolower($rawName);

            // Collect Set-Cookie separately so callers can apply upgradeSessionCookie()
            if ($lower === 'set-cookie') {
                $setCookies[] = $rawValue;
                continue;
            }

            if (isset($responseHopByHop[$lower])) {
                continue;
            }

            $responseHeaders[$rawName][] = $rawValue;
        }

        return [
            'status'     => $status,
            'headers'    => $responseHeaders,
            'setCookies' => $setCookies,
            'body'       => $responseBody,
        ];
    }
}
