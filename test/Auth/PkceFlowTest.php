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

    // ---------------------------------------------------------------------------
    // buildAuthorizationUrl — scope joining
    // ---------------------------------------------------------------------------

    /**
     * Multiple scopes must be joined with a single space character, not a comma.
     * The OAuth 2.0 specification (RFC 6749 §3.3) requires space-separated scope
     * values; a comma-separated list would be rejected by Zitadel.
     */
    public function testBuildAuthorizationUrlJoinsScopesWithSpace(): void
    {
        $config = new ZitadelConfig(
            issuerUrl:    'https://example.zitadel.cloud',
            clientId:     'test-client',
            redirectUri:  'https://myapp.com/zitadel/callback',
            cookieSecret: bin2hex(random_bytes(32)),
            scopes:       ['openid', 'profile', 'email'],
        );

        $url = PkceFlow::buildAuthorizationUrl($config, 'challenge', 'state');

        // The scope query parameter value must use %20 (space) as separator.
        self::assertStringContainsString('scope=openid+profile+email', $url);
        // It must not use a comma as separator.
        self::assertStringNotContainsString('scope=openid,profile,email', $url);
    }

    // ---------------------------------------------------------------------------
    // selectToken — all branches
    // ---------------------------------------------------------------------------

    /**
     * A JWS access_token has exactly 3 dot-separated segments and must be
     * preferred over the id_token when present.
     */
    public function testSelectTokenReturnsAccessTokenWhenJws(): void
    {
        $tokens = [
            'access_token' => 'header.payload.signature',
            'id_token'     => 'id.payload.signature',
        ];

        self::assertSame('header.payload.signature', PkceFlow::selectToken($tokens));
    }

    /**
     * A JWE access_token has 5 dot-separated segments and cannot be validated
     * locally. selectToken() must fall back to the id_token in this case.
     */
    public function testSelectTokenFallsBackToIdTokenForJweAccessToken(): void
    {
        $tokens = [
            'access_token' => 'h.ek.iv.ciphertext.tag',
            'id_token'     => 'id.payload.signature',
        ];

        self::assertSame('id.payload.signature', PkceFlow::selectToken($tokens));
    }

    /**
     * When access_token is absent, selectToken() must return the id_token.
     */
    public function testSelectTokenReturnsIdTokenWhenAccessTokenAbsent(): void
    {
        $tokens = ['id_token' => 'id.payload.signature'];

        self::assertSame('id.payload.signature', PkceFlow::selectToken($tokens));
    }

    /**
     * When neither access_token nor id_token is present, selectToken() must
     * return null.
     */
    public function testSelectTokenReturnsNullWhenNeitherPresent(): void
    {
        self::assertNull(PkceFlow::selectToken([]));
        self::assertNull(PkceFlow::selectToken(['token_type' => 'Bearer']));
    }

    /**
     * When access_token is not a string (e.g. an integer or null), the code
     * falls through to id_token rather than crashing.
     */
    public function testSelectTokenFallsThroughWhenAccessTokenIsNotString(): void
    {
        $tokens = [
            'access_token' => 12345,
            'id_token'     => 'id.payload.signature',
        ];

        self::assertSame('id.payload.signature', PkceFlow::selectToken($tokens));
    }

    /**
     * An access_token consisting only of dots (e.g. "..") has the right number
     * of dot separators but empty segments — it is not a valid JWT and must not
     * be returned. selectToken() must fall back to id_token.
     */
    public function testSelectTokenFallsBackForAllDotsAccessToken(): void
    {
        $tokens = [
            'access_token' => '..',   // 2 dots, 3 empty segments
            'id_token'     => 'id.payload.signature',
        ];

        self::assertSame('id.payload.signature', PkceFlow::selectToken($tokens));
    }

    /**
     * An access_token with a missing middle segment (e.g. "header..signature")
     * has 2 dots but an empty payload — not a valid JWS.
     * selectToken() must fall back to id_token.
     */
    public function testSelectTokenFallsBackForEmptyMiddleSegment(): void
    {
        $tokens = [
            'access_token' => 'header..signature',
            'id_token'     => 'id.payload.signature',
        ];

        self::assertSame('id.payload.signature', PkceFlow::selectToken($tokens));
    }

    /**
     * An access_token with a trailing dot (e.g. "header.payload.") has 2 dots
     * but an empty signature segment — not a valid JWS.
     * selectToken() must fall back to id_token.
     */
    public function testSelectTokenFallsBackForEmptyTrailingSegment(): void
    {
        $tokens = [
            'access_token' => 'header.payload.',
            'id_token'     => 'id.payload.signature',
        ];

        self::assertSame('id.payload.signature', PkceFlow::selectToken($tokens));
    }

    /**
     * An access_token with a leading dot (e.g. ".payload.signature") has 2 dots
     * but an empty header segment — not a valid JWS.
     * selectToken() must fall back to id_token.
     */
    public function testSelectTokenFallsBackForEmptyLeadingSegment(): void
    {
        $tokens = [
            'access_token' => '.payload.signature',
            'id_token'     => 'id.payload.signature',
        ];

        self::assertSame('id.payload.signature', PkceFlow::selectToken($tokens));
    }

    // ---------------------------------------------------------------------------
    // buildAuthorizationUrl — empty scopes
    // ---------------------------------------------------------------------------

    /**
     * An empty `scopes` array must be rejected by the ZitadelConfig constructor.
     * An empty scope list would produce `scope=` in the authorization URL, which
     * OIDC providers reject; surfacing the error at construction time is cleaner.
     */
    public function testZitadelConfigThrowsForEmptyScopes(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/scopes/i');

        new ZitadelConfig(
            issuerUrl:    'https://example.zitadel.cloud',
            clientId:     'test-client',
            redirectUri:  'https://myapp.com/zitadel/callback',
            cookieSecret: bin2hex(random_bytes(32)),
            scopes:       [],
        );
    }

    /**
     * When a single scope is provided it must appear in the URL without a
     * trailing or leading space.
     */
    public function testBuildAuthorizationUrlWithSingleScope(): void
    {
        $config = new ZitadelConfig(
            issuerUrl:    'https://example.zitadel.cloud',
            clientId:     'test-client',
            redirectUri:  'https://myapp.com/zitadel/callback',
            cookieSecret: bin2hex(random_bytes(32)),
            scopes:       ['openid'],
        );

        $url = PkceFlow::buildAuthorizationUrl($config, 'challenge', 'state');

        self::assertStringContainsString('scope=openid', $url);
        // Must not have a space at the start or end of the scope value.
        self::assertStringNotContainsString('scope=+', $url);
        self::assertStringNotContainsString('scope=openid+', $url);
    }
}
