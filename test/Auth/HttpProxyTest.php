<?php

declare(strict_types=1);

namespace Zitadel\Sdk\Test\Auth;

use PHPUnit\Framework\TestCase;
use Zitadel\Sdk\Auth\HttpProxy;

/**
 * Tests for the static helper methods in {@see HttpProxy}.
 *
 * The {@see HttpProxy::forward()} method (cURL I/O) is not unit-tested here;
 * it is covered by the framework integration specs that spin up a real server.
 */
final class HttpProxyTest extends TestCase
{
    // -------------------------------------------------------------------------
    // isProxyPath
    // -------------------------------------------------------------------------

    public function testIsProxyPathMatchesExact(): void
    {
        self::assertTrue(HttpProxy::isProxyPath('/__nextgen', '/__nextgen'));
    }

    public function testIsProxyPathMatchesTrailingSlash(): void
    {
        // A request to /__nextgen/ (trailing slash) should be proxied.
        self::assertTrue(HttpProxy::isProxyPath('/__nextgen/', '/__nextgen'));
    }

    public function testIsProxyPathMatchesSubPath(): void
    {
        self::assertTrue(HttpProxy::isProxyPath('/__nextgen/oauth/v2/keys', '/__nextgen'));
    }

    public function testIsProxyPathMatchesDeepSubPath(): void
    {
        self::assertTrue(HttpProxy::isProxyPath('/__nextgen/oidc/v1/end_session', '/__nextgen'));
    }

    public function testIsProxyPathDoesNotMatchSimilarPrefix(): void
    {
        // /__nextgenother shares the prefix but is a different path — must not match.
        self::assertFalse(HttpProxy::isProxyPath('/__nextgenother', '/__nextgen'));
    }

    public function testIsProxyPathDoesNotMatchUnrelatedPath(): void
    {
        self::assertFalse(HttpProxy::isProxyPath('/dashboard', '/__nextgen'));
    }

    public function testIsProxyPathDoesNotMatchRoot(): void
    {
        self::assertFalse(HttpProxy::isProxyPath('/', '/__nextgen'));
    }

    public function testIsProxyPathDoesNotMatchEmptyPath(): void
    {
        self::assertFalse(HttpProxy::isProxyPath('', '/__nextgen'));
    }

    public function testIsProxyPathWorksWithCustomPrefix(): void
    {
        self::assertTrue(HttpProxy::isProxyPath('/auth-proxy/token', '/auth-proxy'));
        self::assertFalse(HttpProxy::isProxyPath('/auth-proxy-other', '/auth-proxy'));
    }

    public function testIsProxyPathStripsTrailingSlashFromProxyPath(): void
    {
        // proxyPath with a trailing slash should still work correctly.
        self::assertTrue(HttpProxy::isProxyPath('/__nextgen/keys', '/__nextgen/'));
        self::assertTrue(HttpProxy::isProxyPath('/__nextgen', '/__nextgen/'));
    }

    // -------------------------------------------------------------------------
    // upgradeSessionCookie
    // -------------------------------------------------------------------------

    public function testUpgradeAddsSecureFlagOnHttps(): void
    {
        $cookie  = '__nextgen_auth=abc123; HttpOnly; SameSite=Lax';
        $upgraded = HttpProxy::upgradeSessionCookie($cookie, true);

        self::assertSame($cookie . '; Secure', $upgraded);
    }

    public function testUpgradeDoesNotAddSecureFlagOnHttp(): void
    {
        $cookie  = '__nextgen_auth=abc123; HttpOnly; SameSite=Lax';
        $result  = HttpProxy::upgradeSessionCookie($cookie, false);

        self::assertSame($cookie, $result);
    }

    public function testUpgradeDoesNotDoubleSecureFlag(): void
    {
        $cookie = '__nextgen_auth=abc123; HttpOnly; SameSite=Lax; Secure';
        $result = HttpProxy::upgradeSessionCookie($cookie, true);

        self::assertSame($cookie, $result);
    }

    public function testUpgradeIsCaseInsensitiveForExistingSecureFlag(): void
    {
        // Lowercase 'secure' — should not add another Secure.
        $cookie = '__nextgen_auth=abc123; HttpOnly; secure';
        $result = HttpProxy::upgradeSessionCookie($cookie, true);

        self::assertSame($cookie, $result);
    }

    public function testUpgradeIsCaseInsensitiveForMixedCaseSecureFlag(): void
    {
        $cookie = '__nextgen_auth=abc123; HttpOnly; SECURE';
        $result = HttpProxy::upgradeSessionCookie($cookie, true);

        self::assertSame($cookie, $result);
    }

    public function testUpgradeAddsSecureFlagToNonNextgenCookieOnHttps(): void
    {
        // All cookies from the upstream OIDC server — not just __nextgen* ones —
        // must have their Secure flag added when the client-facing connection is
        // HTTPS. This includes CSRF tokens, state cookies, and other cookies that
        // the OIDC server may set under its own names.
        $cookie   = 'session=xyz; HttpOnly; SameSite=Lax';
        $upgraded = HttpProxy::upgradeSessionCookie($cookie, true);

        self::assertSame($cookie . '; Secure', $upgraded);
    }

    public function testUpgradeDoesNotAddSecureFlagToNonNextgenCookieOnHttp(): void
    {
        $cookie = 'session=xyz; HttpOnly; SameSite=Lax';
        $result = HttpProxy::upgradeSessionCookie($cookie, false);

        self::assertSame($cookie, $result);
    }

    public function testUpgradeHandlesAllNextgenCookieVariants(): void
    {
        // __nextgen_pkce is also a __nextgen* cookie and must be upgraded.
        $cookie  = '__nextgen_pkce=state; HttpOnly; SameSite=Strict';
        $upgraded = HttpProxy::upgradeSessionCookie($cookie, true);

        self::assertSame($cookie . '; Secure', $upgraded);
    }

    public function testUpgradeHandlesCookieWithLeadingSpaceInName(): void
    {
        // Spaces before the name are trimmed when checking the prefix.
        $cookie  = ' __nextgen_auth=abc; HttpOnly';
        $upgraded = HttpProxy::upgradeSessionCookie($cookie, true);

        self::assertSame($cookie . '; Secure', $upgraded);
    }

    public function testUpgradeDoesNotTouchCookieThatStartsWithNextgenButIsNotPrefix(): void
    {
        // A cookie named exactly "__nextgen" (no underscore suffix) still matches.
        $cookie  = '__nextgen=value; HttpOnly';
        $upgraded = HttpProxy::upgradeSessionCookie($cookie, true);

        self::assertSame($cookie . '; Secure', $upgraded);
    }
}
