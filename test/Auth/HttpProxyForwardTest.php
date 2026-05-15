<?php

declare(strict_types=1);

namespace Zitadel\Sdk\Test\Auth;

use PHPUnit\Framework\TestCase;
use Zitadel\Sdk\Auth\HttpProxy;

/**
 * Tests for {@see HttpProxy::forward()} using a local PHP echo server.
 *
 * The echo server (`test/fixtures/echo.php`) reflects the request method, path,
 * headers, and body back as JSON, allowing exact assertions on what the proxy
 * actually sends upstream — covering the behaviors that pure unit tests of
 * {@see HttpProxy::isProxyPath()} and {@see HttpProxy::upgradeSessionCookie()}
 * cannot exercise.
 *
 * Covered behaviours:
 * - Hop-by-hop headers stripped from the forwarded request
 * - SDK-internal `x-nextgen-auth-token` header stripped from the forwarded request
 * - `X-Forwarded-For` chain built, appended, and preserved correctly
 * - `X-Forwarded-Host` and `X-Forwarded-Proto` injected only when absent
 * - Request body forwarded for POST; empty body forwarded for DELETE (not omitted)
 * - Multiple upstream `Set-Cookie` headers collected as separate entries
 */
final class HttpProxyForwardTest extends TestCase
{
    private static int $port;

    /** @var resource|false */
    private static mixed $process = false;

    // ── Lifecycle ─────────────────────────────────────────────────────────────

    public static function setUpBeforeClass(): void
    {
        parent::setUpBeforeClass();

        self::$port = self::findFreePort();

        $script  = __DIR__ . '/../fixtures/echo.php';
        $logFile = sys_get_temp_dir() . '/zitadel_echo_' . self::$port . '.log';

        self::$process = proc_open(
            sprintf(
                '%s -d xdebug.mode=off -S 127.0.0.1:%d %s',
                PHP_BINARY,
                self::$port,
                escapeshellarg($script),
            ),
            [
                0 => ['file', '/dev/null', 'r'],
                1 => ['file', $logFile, 'w'],
                2 => ['file', $logFile, 'w'],
            ],
            $pipes,
        );

        // Wait up to 5 s for the server to accept connections.
        $deadline = time() + 5;

        while (time() < $deadline) {
            $ch = curl_init('http://127.0.0.1:' . self::$port . '/');
            curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 1, CURLOPT_CONNECTTIMEOUT => 1]);
            $ok = curl_exec($ch) !== false;
            unset($ch); // curl_close() is deprecated in PHP 8.5+; unset frees the handle

            if ($ok) {
                break;
            }

            usleep(100_000);
        }
    }

    public static function tearDownAfterClass(): void
    {
        if (is_resource(self::$process)) {
            proc_terminate(self::$process);
            proc_close(self::$process);
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static function findFreePort(): int
    {
        $server = stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);

        if ($server === false) {
            throw new \RuntimeException("Could not bind a free port: {$errstr} (errno {$errno})");
        }

        $addr = stream_socket_get_name($server, false);
        fclose($server);

        if ($addr === false) {
            throw new \RuntimeException('stream_socket_get_name() returned false');
        }

        $parts = explode(':', $addr);

        return (int) end($parts);
    }

    private function echoUrl(): string
    {
        return 'http://127.0.0.1:' . self::$port . '/';
    }

    /**
     * Calls HttpProxy::forward() against the local echo server and returns
     * the decoded JSON payload.
     *
     * @param array<string,string> $headers
     * @return array{method: string, path: string, headers: array<string,string>, body: string}
     */
    private function echo(
        string $method,
        array  $headers = [],
        string $body = '',
        string $remoteAddr = '1.2.3.4',
        string $host = 'myapp.example.com',
        string $proto = 'http',
    ): array {
        $result = HttpProxy::forward($method, $this->echoUrl(), $headers, $body, $remoteAddr, $host, $proto, 5);
        self::assertSame(200, $result['status'], 'Echo server must return 200');
        /** @var array{method: string, path: string, headers: array<string,string>, body: string}|null $decoded */
        $decoded = json_decode($result['body'], true);
        self::assertIsArray($decoded, 'Echo server must return valid JSON');

        return $decoded;
    }

    // ── Hop-by-hop header stripping ───────────────────────────────────────────

    /**
     * RFC 7230 hop-by-hop headers must never be forwarded to the upstream.
     * The test sends `Proxy-Authenticate` and `Keep-Alive` (both in HOP_BY_HOP)
     * alongside a regular header (`Accept`) that must still be forwarded.
     */
    public function testHopByHopHeadersNotForwardedToUpstream(): void
    {
        $echo = $this->echo('GET', [
            'Proxy-Authenticate' => 'Basic realm="test"',
            'Keep-Alive'         => 'timeout=5',
            'Accept'             => 'application/json',
        ]);

        self::assertArrayNotHasKey(
            'proxy-authenticate',
            $echo['headers'],
            'Proxy-Authenticate (hop-by-hop) must be stripped from the forwarded request',
        );
        self::assertArrayNotHasKey(
            'keep-alive',
            $echo['headers'],
            'Keep-Alive (hop-by-hop) must be stripped from the forwarded request',
        );
        self::assertArrayHasKey(
            'accept',
            $echo['headers'],
            'Non-hop-by-hop headers must still be forwarded to the upstream',
        );
    }

    // ── Internal header stripping ─────────────────────────────────────────────

    /**
     * `x-nextgen-auth-token` is an SDK-private header used to tunnel the validated
     * session between the middleware and server components. If a malicious client
     * sends it directly, the proxy must strip it before forwarding — otherwise the
     * upstream could be tricked into treating an unauthenticated request as authenticated.
     */
    public function testInternalHeaderNotForwardedToUpstream(): void
    {
        $echo = $this->echo('GET', [
            'X-Nextgen-Auth-Token' => 'leaked-secret',
            'Accept'               => 'text/plain',
        ]);

        self::assertArrayNotHasKey(
            'x-nextgen-auth-token',
            $echo['headers'],
            'x-nextgen-auth-token must be stripped and never forwarded to the upstream',
        );
        self::assertArrayHasKey(
            'accept',
            $echo['headers'],
            'Non-internal headers must still be forwarded to the upstream',
        );
    }

    // ── X-Forwarded-For chain building ────────────────────────────────────────

    public function testXffSetFromRemoteAddr(): void
    {
        $echo = $this->echo('GET', [], '', '203.0.113.1');

        self::assertSame(
            '203.0.113.1',
            $echo['headers']['x-forwarded-for'] ?? '',
            'X-Forwarded-For must be set to the direct client IP when no existing chain is present',
        );
    }

    public function testXffAppendsToExistingChain(): void
    {
        // A CDN or load balancer upstream may have already set X-Forwarded-For.
        // The proxy must append the direct client IP rather than replacing the chain.
        $echo = $this->echo('GET', [
            'X-Forwarded-For' => '10.0.0.1, 10.0.0.2',
        ], '', '203.0.113.99');

        self::assertSame(
            '10.0.0.1, 10.0.0.2, 203.0.113.99',
            $echo['headers']['x-forwarded-for'] ?? '',
            'X-Forwarded-For must append remoteAddr to the existing chain, not replace it',
        );
    }

    public function testXffPreservesExistingChainWhenRemoteAddrIsEmpty(): void
    {
        // When the direct client IP is unknown (e.g. Unix-socket SAPI), the existing
        // chain must be preserved unchanged so upstream audit logs are not corrupted.
        $echo = $this->echo('GET', [
            'X-Forwarded-For' => '10.0.0.1',
        ], '', '');

        self::assertSame(
            '10.0.0.1',
            $echo['headers']['x-forwarded-for'] ?? '',
            'Existing X-Forwarded-For must be preserved when remoteAddr is empty',
        );
    }

    public function testXffNotSetWhenBothRemoteAddrAndExistingChainAreAbsent(): void
    {
        $echo = $this->echo('GET', [], '', '');

        self::assertArrayNotHasKey(
            'x-forwarded-for',
            $echo['headers'],
            'X-Forwarded-For must not be injected when remoteAddr is empty and no existing chain is present',
        );
    }

    // ── X-Forwarded-Host injection ────────────────────────────────────────────

    public function testXforwardedHostInjectedWhenAbsent(): void
    {
        $echo = $this->echo('GET', [], '', '1.2.3.4', 'myapp.example.com:8443');

        self::assertSame(
            'myapp.example.com:8443',
            $echo['headers']['x-forwarded-host'] ?? '',
            'X-Forwarded-Host must be injected from the $host parameter when not already present',
        );
    }

    public function testXforwardedHostNotOverriddenWhenAlreadyPresent(): void
    {
        // A load balancer upstream of PHP may have set X-Forwarded-Host already.
        // The proxy must preserve it rather than overwriting with the local host.
        $echo = $this->echo('GET', [
            'X-Forwarded-Host' => 'cdn.example.com',
        ], '', '1.2.3.4', 'origin.example.com');

        self::assertSame(
            'cdn.example.com',
            $echo['headers']['x-forwarded-host'] ?? '',
            'X-Forwarded-Host set by an upstream proxy must be preserved unchanged',
        );
    }

    // ── X-Forwarded-Proto injection ───────────────────────────────────────────

    public function testXforwardedProtoInjectedWhenAbsent(): void
    {
        $echo = $this->echo('GET', [], '', '1.2.3.4', 'host', 'https');

        self::assertSame(
            'https',
            $echo['headers']['x-forwarded-proto'] ?? '',
            'X-Forwarded-Proto must be injected from the $proto parameter when not already present',
        );
    }

    public function testXforwardedProtoNotOverriddenWhenAlreadyPresent(): void
    {
        $echo = $this->echo('GET', [
            'X-Forwarded-Proto' => 'https',
        ], '', '1.2.3.4', 'host', 'http');

        self::assertSame(
            'https',
            $echo['headers']['x-forwarded-proto'] ?? '',
            'X-Forwarded-Proto set by an upstream proxy must be preserved unchanged',
        );
    }

    // ── Request body forwarding ───────────────────────────────────────────────

    public function testPostBodyForwardedToUpstream(): void
    {
        $echo = $this->echo('POST', ['Content-Type' => 'application/json'], '{"key":"value"}');

        self::assertSame(
            '{"key":"value"}',
            $echo['body'],
            'POST body must be forwarded to the upstream unchanged',
        );
    }

    /**
     * DELETE is a non-GET/HEAD method with no body. `CURLOPT_POSTFIELDS` must still
     * be set to `''` so the request carries `Content-Length: 0`, matching the
     * Fetch API's behaviour (which sends an empty body rather than omitting it).
     *
     * This test guards against the previously fixed `$body !== ''` guard that
     * silently skipped `CURLOPT_POSTFIELDS` for empty-body non-GET/HEAD requests.
     */
    public function testEmptyBodyForwardedForDeleteRequest(): void
    {
        $echo = $this->echo('DELETE', []);

        self::assertSame(
            'DELETE',
            $echo['method'],
            'DELETE method must be forwarded to the upstream',
        );
        self::assertSame(
            '',
            $echo['body'],
            'Empty body must be forwarded (not omitted) for DELETE requests',
        );
    }

    // ── Multiple Set-Cookie header isolation ──────────────────────────────────

    /**
     * When the upstream emits multiple `Set-Cookie` headers, each must appear as
     * a separate entry in the `setCookies` array returned by `forward()`.
     *
     * Collapsing them into a single comma-joined value would break cookie parsing
     * because cookie values may themselves contain commas.
     */
    public function testMultipleSetCookieHeadersCollectedSeparately(): void
    {
        // Ask the echo server to emit two Set-Cookie headers.
        $result = HttpProxy::forward(
            'GET',
            $this->echoUrl(),
            ['X-Echo-Cookies' => '2'],
            '',
            '1.2.3.4',
            'host',
            'http',
            5,
        );

        self::assertCount(
            2,
            $result['setCookies'],
            'Each Set-Cookie header from the upstream must be a separate entry in the setCookies array',
        );
        self::assertStringContainsString('__nextgen_cookie1=', $result['setCookies'][0]);
        self::assertStringContainsString('__nextgen_cookie2=', $result['setCookies'][1]);
    }
}
