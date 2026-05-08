<?php

declare(strict_types=1);

namespace Zitadel\Sdk\Test\Auth;

use PHPUnit\Framework\TestCase;
use Zitadel\Sdk\Auth\PkceFlow;
use Zitadel\Sdk\Config\ZitadelConfig;

final class PkceFlowTest extends TestCase
{
    private ZitadelConfig $config;

    protected function setUp(): void
    {
        $this->config = new ZitadelConfig(
            issuerUrl:    'https://example.zitadel.cloud',
            clientId:     'test-client',
            redirectUri:  'https://myapp.com/zitadel/callback',
            cookieSecret: bin2hex(random_bytes(32)),
        );
    }

    public function testGenerateCodeVerifierLength(): void
    {
        $verifier = PkceFlow::generateCodeVerifier();
        self::assertSame(43, strlen($verifier));
    }

    public function testGenerateCodeVerifierCharset(): void
    {
        $verifier = PkceFlow::generateCodeVerifier();
        self::assertMatchesRegularExpression('/^[A-Za-z0-9\-_]+$/', $verifier);
        self::assertStringNotContainsString('=', $verifier);
    }

    public function testGenerateCodeVerifierIsRandom(): void
    {
        $v1 = PkceFlow::generateCodeVerifier();
        $v2 = PkceFlow::generateCodeVerifier();
        self::assertNotSame($v1, $v2);
    }

    public function testGenerateStateLength(): void
    {
        $state = PkceFlow::generateState();
        self::assertSame(43, strlen($state));
    }

    public function testGenerateStateIsRandom(): void
    {
        $s1 = PkceFlow::generateState();
        $s2 = PkceFlow::generateState();
        self::assertNotSame($s1, $s2);
    }

    public function testGenerateCodeChallengeIsS256(): void
    {
        $verifier  = PkceFlow::generateCodeVerifier();
        $challenge = PkceFlow::generateCodeChallenge($verifier);

        $expected = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
        self::assertSame($expected, $challenge);
    }

    public function testGenerateCodeChallengeHasNoEqualsSign(): void
    {
        $challenge = PkceFlow::generateCodeChallenge(PkceFlow::generateCodeVerifier());
        self::assertStringNotContainsString('=', $challenge);
    }

    public function testBuildAuthorizationUrlContainsRequiredParams(): void
    {
        $challenge = PkceFlow::generateCodeChallenge(PkceFlow::generateCodeVerifier());
        $state     = PkceFlow::generateState();
        $url       = PkceFlow::buildAuthorizationUrl($this->config, $challenge, $state);

        self::assertStringContainsString('https://example.zitadel.cloud/oauth/v2/authorize', $url);
        self::assertStringContainsString('response_type=code', $url);
        self::assertStringContainsString('code_challenge_method=S256', $url);
        self::assertStringContainsString('code_challenge=' . urlencode($challenge), $url);
        self::assertStringContainsString('state=' . urlencode($state), $url);
        self::assertStringContainsString('client_id=test-client', $url);
        self::assertStringContainsString('redirect_uri=' . urlencode('https://myapp.com/zitadel/callback'), $url);
        self::assertStringContainsString('scope=openid', $url);
    }
}
