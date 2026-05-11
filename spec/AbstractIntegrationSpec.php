<?php

declare(strict_types=1);

namespace Zitadel\Sdk\Spec;

use PHPUnit\Framework\TestCase;
use Playwright\Browser\BrowserInterface;
use Playwright\Page\PageInterface;
use Playwright\PlaywrightFactory;
use Playwright\PlaywrightClient;
use Testcontainers\Container\GenericContainer;

/**
 * Base class for all integration specs.
 *
 * Each subclass provides its fixture directory and port. This class manages
 * the complete test lifecycle:
 *
 * 1. `setUpBeforeClass()` starts a navikt/mock-oauth2-server container via
 *    Testcontainers, writes a `.env` file to the fixture directory with the
 *    dynamically-assigned mock server URL, installs composer dependencies if
 *    needed, starts a PHP built-in server for the fixture app, waits for
 *    the health endpoint to respond, then launches a headless Chromium browser
 *    via Playwright.
 *
 * 2. Tests exercise the PKCE flow using Playwright with isolated browser
 *    contexts, following the full redirect chain: /dashboard → mock auth
 *    server login form → callback → /dashboard.
 *
 * 3. `tearDownAfterClass()` closes the browser, stops the Playwright server,
 *    terminates the PHP server process, and stops the Testcontainers container.
 */
abstract class AbstractIntegrationSpec extends TestCase
{
    /** @var array<class-string, GenericContainer> */
    private static array $mockServers = [];

    /** @var array<class-string, string> */
    private static array $mockBaseUrls = [];

    /** @var array<class-string, resource> */
    private static array $phpProcesses = [];

    /** @var array<class-string, PlaywrightClient> */
    private static array $playwrightClients = [];

    /** @var array<class-string, BrowserInterface> */
    private static array $browsers = [];

    /** Returns the absolute path to the fixture app directory. */
    abstract protected static function fixtureDir(): string;

    /** Returns the port the fixture app runs on. */
    abstract protected static function fixturePort(): int;

    /** Returns framework-specific additional env vars to write alongside the ZITADEL_* vars. */
    protected static function extraEnvVars(string $mockBaseUrl, int $port): array
    {
        return [];
    }

    protected function baseUrl(): string
    {
        return 'http://localhost:' . static::fixturePort();
    }

    protected function port(): int
    {
        return static::fixturePort();
    }

    protected function mockBaseUrl(): string
    {
        return self::$mockBaseUrls[static::class];
    }

    // ── Lifecycle ──────────────────────────────────────────────────────────────

    public static function setUpBeforeClass(): void
    {
        parent::setUpBeforeClass();

        $class = static::class;

        // Start navikt/mock-oauth2-server
        $container = (new GenericContainer('ghcr.io/navikt/mock-oauth2-server:2.1.10'))
            ->withExposedPorts(8080)
            ->start();

        $mockHost = $container->getHost();
        $mockPort = $container->getMappedPort(8080);
        $mockBase = "http://{$mockHost}:{$mockPort}";

        self::waitForHttp("{$mockBase}/", 405);

        self::$mockServers[$class]   = $container;
        self::$mockBaseUrls[$class]  = $mockBase;

        // Write .env for the fixture app
        static::writeEnvFile(static::fixtureDir(), static::fixturePort(), $mockBase);

        // Install composer deps if vendor/ doesn't exist yet
        $fixtureDir = static::fixtureDir();
        if (!is_dir($fixtureDir . '/vendor')) {
            exec(
                sprintf(
                    'composer install --working-dir=%s --no-interaction --quiet 2>&1',
                    escapeshellarg($fixtureDir)
                )
            );
        }

        if (!is_file($fixtureDir . '/vendor/autoload.php')) {
            self::markTestSkipped(
                static::class . ': composer install failed for fixture at ' . $fixtureDir .
                ' — check that all required PHP extensions and packages are available.'
            );
        }

        // Start PHP built-in server
        $docRoot    = $fixtureDir . '/public';
        $port       = static::fixturePort();
        $logFile = sys_get_temp_dir() . '/zitadel_fixture_' . static::fixturePort() . '.log';
        $descriptors = [
            0 => ['file', '/dev/null', 'r'],
            1 => ['file', $logFile, 'w'],
            2 => ['file', $logFile, 'w'],
        ];
        $process = proc_open(
            sprintf(
                '%s -d xdebug.mode=off -d display_errors=0 -S localhost:%d -t %s',
                PHP_BINARY,
                $port,
                escapeshellarg($docRoot),
            ),
            $descriptors,
            $pipes,
            $fixtureDir
        );

        self::$phpProcesses[$class] = $process;

        // Wait for the fixture app's health endpoint
        self::waitForHttp("http://localhost:{$port}/health", 200, 30);

        // Launch headless Chromium via Playwright
        $client  = PlaywrightFactory::create();
        $browser = $client->chromium()->withHeadless(true)->launch();

        self::$playwrightClients[$class] = $client;
        self::$browsers[$class]          = $browser;
    }

    public static function tearDownAfterClass(): void
    {
        $class = static::class;

        if (isset(self::$browsers[$class])) {
            self::$browsers[$class]->close();
            unset(self::$browsers[$class]);
        }

        if (isset(self::$playwrightClients[$class])) {
            self::$playwrightClients[$class]->close();
            unset(self::$playwrightClients[$class]);
        }

        if (isset(self::$phpProcesses[$class]) && is_resource(self::$phpProcesses[$class])) {
            proc_terminate(self::$phpProcesses[$class]);
            proc_close(self::$phpProcesses[$class]);
            unset(self::$phpProcesses[$class]);
        }

        if (isset(self::$mockServers[$class])) {
            self::$mockServers[$class]->stop();
            unset(self::$mockServers[$class]);
        }

        parent::tearDownAfterClass();
    }

    // ── Tests ──────────────────────────────────────────────────────────────────

    public function testHealthIsPublic(): void
    {
        $page     = $this->newPage();
        $response = $page->goto($this->baseUrl() . '/health');
        self::assertNotNull($response);
        self::assertSame(200, $response->status());
        self::assertStringContainsString('OK', $page->locator('body')->innerText());
    }

    public function testDashboardRedirectsWhenUnauthenticated(): void
    {
        $page = $this->newPage();
        $page->goto($this->baseUrl() . '/dashboard');
        self::assertStringContainsString('/authorize', $page->url());
    }

    public function testAuthorizationUrlContainsRequiredParams(): void
    {
        $page = $this->newPage();
        $page->goto($this->baseUrl() . '/dashboard');
        $url = $page->url();

        self::assertStringContainsString('response_type=code', $url);
        self::assertStringContainsString('code_challenge_method=S256', $url);
        self::assertStringContainsString('state=', $url);
        self::assertStringContainsString('code_challenge=', $url);
    }

    public function testFullPkceFlow(): void
    {
        $page = $this->newPage();

        // Step 1: GET /dashboard — should redirect to mock auth server login form
        $page->goto($this->baseUrl() . '/dashboard');
        $page->waitForSelector('input[name="username"]');

        // Step 2: Fill the navikt login form and submit
        $claims = json_encode(['name' => 'Alice Test', 'email' => 'alice@example.com']);
        $page->locator('input[name="username"]')->fill('alice');
        $page->locator('textarea[name="claims"]')->fill((string) $claims);
        $page->locator('input[type="submit"]')->click();

        // Step 3: Callback exchanges code and sets cookie; browser follows redirect to /dashboard
        $page->waitForURL($this->baseUrl() . '/dashboard');

        // Step 4: Authenticated page must contain the greeting, email, and sub claims
        $body = $page->locator('body')->innerText();
        self::assertStringContainsString('Hello Alice Test', $body);
        self::assertStringContainsString('alice@example.com', $body);
        self::assertStringContainsString('sub:', $body);
    }

    public function testLogoutClearsCookieAndRedirects(): void
    {
        $page = $this->newPage();

        // Authenticate first
        $page->goto($this->baseUrl() . '/dashboard');
        $page->waitForSelector('input[name="username"]');
        $claims = json_encode(['name' => 'Alice Test', 'email' => 'alice@example.com']);
        $page->locator('input[name="username"]')->fill('alice');
        $page->locator('textarea[name="claims"]')->fill((string) $claims);
        $page->locator('input[type="submit"]')->click();
        $page->waitForURL($this->baseUrl() . '/dashboard');
        self::assertStringContainsString('Hello', $page->locator('body')->innerText(), 'pre-logout sanity check');

        // Logout — clears __nextgen_auth cookie, redirects through end-session
        $page->goto($this->baseUrl() . '/zitadel/logout');

        // /dashboard must redirect to auth again
        $page->goto($this->baseUrl() . '/dashboard');
        self::assertStringContainsString('/authorize', $page->url());
    }

    public function testHomeIsAccessibleWithoutAuth(): void
    {
        $page     = $this->newPage();
        $response = $page->goto($this->baseUrl() . '/home');
        self::assertNotNull($response);
        self::assertSame(200, $response->status());
        // Final URL must still be /home — Playwright follows redirects, so if the middleware
        // incorrectly redirected to /authorize the URL would have changed.
        self::assertSame($this->baseUrl() . '/home', $page->url());
        self::assertStringContainsString('Welcome home', $page->locator('body')->innerText());
    }

    public function testApiWithoutTokenReturnsUnauthenticated(): void
    {
        $ch = curl_init($this->baseUrl() . '/api');
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER  => true,
            CURLOPT_TIMEOUT         => 5,
            CURLOPT_FOLLOWLOCATION  => false,
        ]);
        $apiBody  = curl_exec($ch);
        $httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        self::assertNotFalse($apiBody, '/api endpoint must be reachable without a token');
        self::assertSame(200, $httpCode, '/api must return 200 for anonymous access, not a redirect');

        $apiResponse = json_decode((string) $apiBody, true);
        self::assertIsArray($apiResponse);
        self::assertFalse(
            $apiResponse['authenticated'],
            '/api without a token must return authenticated=false'
        );
    }

    public function testApiBearerTokenAccess(): void
    {
        // Issue a signed JWT directly from the navikt mock-oauth2-server
        $ch = curl_init($this->mockBaseUrl() . '/default/token');
        curl_setopt_array($ch, [
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => http_build_query([
                'grant_type'    => 'client_credentials',
                'client_id'     => 'test-client',
                'client_secret' => 'test-secret',
            ]),
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => 5,
            CURLOPT_HTTPHEADER     => ['Content-Type: application/x-www-form-urlencoded'],
        ]);
        $body = curl_exec($ch);
        self::assertNotFalse($body, 'Mock server token endpoint must be reachable');

        $tokenResponse = json_decode((string) $body, true);
        self::assertIsArray($tokenResponse);
        self::assertArrayHasKey('access_token', $tokenResponse, 'Mock server must issue an access_token');
        $jwt = (string) $tokenResponse['access_token'];

        // Send that JWT to /api as a Bearer token
        $ch2 = curl_init($this->baseUrl() . '/api');
        curl_setopt_array($ch2, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => 5,
            CURLOPT_HTTPHEADER     => ["Authorization: Bearer {$jwt}"],
        ]);
        $apiBody = curl_exec($ch2);
        self::assertNotFalse($apiBody, '/api endpoint must be reachable');

        $contentType = (string) curl_getinfo($ch2, CURLINFO_CONTENT_TYPE);
        self::assertStringContainsString(
            'application/json',
            $contentType,
            '/api must respond with Content-Type: application/json'
        );

        $apiResponse = json_decode((string) $apiBody, true);
        self::assertIsArray($apiResponse);
        self::assertTrue(
            $apiResponse['authenticated'],
            'JWKS-validated Bearer token must yield authenticated=true'
        );
        self::assertNotEmpty($apiResponse['sub'], 'Authenticated response must include a non-empty sub');
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    /** Returns a fresh isolated browser context (clean cookies) for a single test. */
    private function newPage(): PageInterface
    {
        return self::$browsers[static::class]->newContext()->newPage();
    }

    // ── Static helpers ─────────────────────────────────────────────────────────

    private static function writeEnvFile(string $fixtureDir, int $port, string $mockBaseUrl): void
    {
        $cookieSecret = bin2hex(random_bytes(32));
        $appKey       = 'base64:' . base64_encode(random_bytes(32));

        $lines = [
            "ZITADEL_ISSUER_URL={$mockBaseUrl}/default",
            "ZITADEL_CLIENT_ID=test-client",
            "ZITADEL_REDIRECT_URI=http://localhost:{$port}/zitadel/callback",
            "ZITADEL_COOKIE_SECRET={$cookieSecret}",
            // Paths are relative to issuerUrl — navikt serves at /default/jwks, /default/authorize etc.
            'ZITADEL_JWKS_PATH=/jwks',
            'ZITADEL_AUTHORIZATION_PATH=/authorize',
            'ZITADEL_TOKEN_PATH=/token',
            'ZITADEL_END_SESSION_PATH=/endsession',
        ];

        foreach (static::extraEnvVars($mockBaseUrl, $port) as $line) {
            $lines[] = $line;
        }

        // Symfony-specific — must come first; phpdotenv createImmutable() keeps first occurrence
        $lines[] = 'APP_ENV=dev';
        $lines[] = 'APP_SECRET=' . bin2hex(random_bytes(16));
        $lines[] = 'APP_DEBUG=1';

        // Laravel-specific (APP_ENV=dev from above is already set; remaining vars are Laravel-only)
        $lines[] = "APP_KEY={$appKey}";
        $lines[] = 'APP_NAME=ZitadelFixture';
        $lines[] = 'APP_DEBUG=true';
        $lines[] = "APP_URL=http://localhost:{$port}";
        $lines[] = 'SESSION_DRIVER=file';

        // CodeIgniter-specific
        $lines[] = 'CI_ENVIRONMENT=development';

        file_put_contents($fixtureDir . '/.env', implode("\n", $lines) . "\n");
    }

    /**
     * Polls a URL until it returns the expected status code, or throws on timeout.
     */
    private static function waitForHttp(string $url, int $expectedStatus, int $maxWaitSeconds = 60): void
    {
        $deadline = time() + $maxWaitSeconds;

        while (time() < $deadline) {
            $ch = curl_init();
            curl_setopt_array($ch, [
                CURLOPT_URL            => $url,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT        => 2,
                CURLOPT_SSL_VERIFYPEER => false,
            ]);
            curl_exec($ch);
            $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);

            if ($status === $expectedStatus) {
                return;
            }

            usleep(500_000); // 0.5 s
        }

        throw new \RuntimeException(
            "Timed out waiting for {$url} to return HTTP {$expectedStatus} (waited {$maxWaitSeconds}s)"
        );
    }
}
