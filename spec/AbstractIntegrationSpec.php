<?php

declare(strict_types=1);

namespace Zitadel\Sdk\Spec;

use PHPUnit\Framework\TestCase;

/**
 * Base class for all integration specs.
 *
 * Each subclass boots a fixture application (via Testcontainers or a built-in
 * server) and a Playwright browser, then exercises the PKCE flow end-to-end.
 *
 * The following tests are common to all framework integrations:
 * - Unauthenticated access to `/health` returns 200 (no redirect)
 * - Unauthenticated access to `/dashboard` redirects to Zitadel authorization endpoint
 * - Zitadel authorization URL contains correct `client_id`, `redirect_uri`, `state`, and `code_challenge`
 * - Completing the PKCE flow sets `__nextgen_auth` cookie and loads `/dashboard`
 * - `/dashboard` returns "Hello <name>" after login
 * - `/zitadel/logout` clears the cookie and redirects to `post_logout_redirect`
 * - Re-visiting `/dashboard` after logout redirects to Zitadel again
 */
abstract class AbstractIntegrationSpec extends TestCase
{
    /** Base URL of the fixture application under test (e.g. http://localhost:9001). */
    abstract protected function baseUrl(): string;

    /** Port the fixture app runs on. */
    abstract protected function port(): int;

    public function testHealthIsPublic(): void
    {
        $response = $this->get('/health');
        self::assertSame(200, $response['status']);
    }

    public function testDashboardRedirectsWhenUnauthenticated(): void
    {
        $response = $this->get('/dashboard', followRedirects: false);
        self::assertSame(302, $response['status']);
        self::assertStringContainsString('/oauth/v2/authorize', $response['location'] ?? '');
    }

    public function testAuthorizationUrlContainsRequiredParams(): void
    {
        $response = $this->get('/dashboard', followRedirects: false);
        $location = $response['location'] ?? '';

        self::assertStringContainsString('response_type=code', $location);
        self::assertStringContainsString('code_challenge_method=S256', $location);
        self::assertStringContainsString('state=', $location);
        self::assertStringContainsString('code_challenge=', $location);
    }

    /**
     * Makes a simple GET request to the fixture app.
     *
     * @return array{status: int, body: string, location: string|null, cookies: array}
     */
    protected function get(string $path, bool $followRedirects = true): array
    {
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL            => $this->baseUrl() . $path,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADER         => true,
            CURLOPT_FOLLOWLOCATION => $followRedirects,
            CURLOPT_TIMEOUT        => 10,
        ]);

        $raw    = (string) curl_exec($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $hdrLen = (int) curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        curl_close($ch);

        $headers  = substr($raw, 0, $hdrLen);
        $body     = substr($raw, $hdrLen);
        $location = null;

        if (preg_match('/^Location:\s*(.+)$/im', $headers, $m)) {
            $location = trim($m[1]);
        }

        return ['status' => $status, 'body' => $body, 'location' => $location, 'headers' => $headers];
    }
}
