<?php

declare(strict_types=1);

namespace Zitadel\Sdk\Test\Auth;

use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Zitadel\Sdk\Auth\PkceStateCookie;

final class PkceStateCookieTest extends TestCase
{
    private string $secret;

    protected function setUp(): void
    {
        $this->secret = bin2hex(random_bytes(32));
    }

    public function testEncryptDecryptRoundtrip(): void
    {
        $verifier = 'test-verifier-value';
        $state    = 'test-state-value';
        $next     = '/dashboard?tab=settings';

        $encoded  = PkceStateCookie::encrypt($verifier, $state, $next, $this->secret);
        $decoded  = PkceStateCookie::decrypt($encoded, $this->secret);

        self::assertNotNull($decoded);
        self::assertSame($verifier, $decoded['verifier']);
        self::assertSame($state, $decoded['state']);
        self::assertSame($next, $decoded['next']);
    }

    public function testEncryptProducesBase64UrlOutput(): void
    {
        $encoded = PkceStateCookie::encrypt('v', 's', '/next', $this->secret);
        self::assertMatchesRegularExpression('/^[A-Za-z0-9\-_]+$/', $encoded);
        self::assertStringNotContainsString('=', $encoded);
        self::assertStringNotContainsString('+', $encoded);
        self::assertStringNotContainsString('/', $encoded);
    }

    public function testEncryptProducesRandomOutputForSameInput(): void
    {
        $e1 = PkceStateCookie::encrypt('v', 's', '/next', $this->secret);
        $e2 = PkceStateCookie::encrypt('v', 's', '/next', $this->secret);
        self::assertNotSame($e1, $e2);
    }

    public function testDecryptReturnsNullForTamperedCiphertext(): void
    {
        $encoded = PkceStateCookie::encrypt('verifier', 'state', '/next', $this->secret);
        // Flip a byte in the middle
        $bytes          = base64_decode(strtr($encoded, '-_', '+/') . '==');
        $bytes[20]      = chr(ord($bytes[20]) ^ 0xFF);
        $tampered = rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');

        self::assertNull(PkceStateCookie::decrypt($tampered, $this->secret));
    }

    public function testDecryptReturnsNullForWrongKey(): void
    {
        $encoded = PkceStateCookie::encrypt('verifier', 'state', '/next', $this->secret);
        $wrongKey = bin2hex(random_bytes(32));

        self::assertNull(PkceStateCookie::decrypt($encoded, $wrongKey));
    }

    public function testDecryptReturnsNullForGarbage(): void
    {
        self::assertNull(PkceStateCookie::decrypt('not-valid-at-all', $this->secret));
        self::assertNull(PkceStateCookie::decrypt('', $this->secret));
    }

    // ---------------------------------------------------------------------------
    // hex2bin guard — invalid cookieSecret must throw immediately
    // ---------------------------------------------------------------------------

    /**
     * Before the fix, hex2bin() returned false on a non-hex string; (string) false
     * produced "" which was passed as a zero-length key to libsodium, causing an
     * opaque SodiumException deep inside encrypt(). The guard must surface this
     * as an InvalidArgumentException at the point of the bad argument.
     */
    public function testEncryptThrowsForInvalidHexSecret(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/cookieSecret/i');

        PkceStateCookie::encrypt('verifier', 'state', '/next', 'not-valid-hex!');
    }

    public function testDecryptThrowsForInvalidHexSecret(): void
    {
        // Produce a valid ciphertext with the correct key first.
        $encoded = PkceStateCookie::encrypt('verifier', 'state', '/next', $this->secret);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/cookieSecret/i');

        // Pass the valid ciphertext but a garbage decryption key.
        PkceStateCookie::decrypt($encoded, 'not-valid-hex!');
    }

    public function testEncryptThrowsForOddLengthHexSecret(): void
    {
        // hex2bin() returns false for odd-length strings regardless of character set.
        $this->expectException(\InvalidArgumentException::class);

        PkceStateCookie::encrypt('verifier', 'state', '/next', 'abc');
    }

    // ---------------------------------------------------------------------------
    // PSR-7 layer — write(), read(), delete()
    // ---------------------------------------------------------------------------

    /**
     * When $secure is true, the Set-Cookie header produced by write() must
     * contain the "; Secure" attribute so the browser only sends the cookie
     * over HTTPS connections.
     */
    public function testWriteWithSecureTrueProducesSecureFlag(): void
    {
        $response = PkceStateCookie::write(
            new Response(200),
            'verifier',
            'state',
            '/next',
            $this->secret,
            true,
        );

        $header = $response->getHeaderLine('Set-Cookie');
        self::assertStringContainsString('; Secure', $header);
    }

    /**
     * When $secure is false the Set-Cookie header must NOT contain "; Secure"
     * because browsers refuse to store Secure cookies on plain-HTTP connections,
     * which would break the auth flow entirely.
     */
    public function testWriteWithSecureFalseOmitsSecureFlag(): void
    {
        $response = PkceStateCookie::write(
            new Response(200),
            'verifier',
            'state',
            '/next',
            $this->secret,
            false,
        );

        $header = $response->getHeaderLine('Set-Cookie');
        self::assertStringNotContainsString('; Secure', $header);
    }

    /**
     * read() must return null when the cookie name is absent from the request,
     * rather than passing an empty/null value to decrypt() which would throw or
     * return an unexpected result.
     */
    public function testReadReturnsNullWhenCookieAbsent(): void
    {
        $request = new ServerRequest('GET', 'https://myapp.com/');

        self::assertNull(PkceStateCookie::read($request, $this->secret));
    }

    /**
     * delete() must produce a Set-Cookie header with Max-Age=0 so the browser
     * immediately expires the cookie. Any other Max-Age (or absence of it) would
     * leave the cookie alive in the browser.
     */
    public function testDeleteProducesMaxAgeZero(): void
    {
        $response = PkceStateCookie::delete(new Response(200));

        $header = $response->getHeaderLine('Set-Cookie');
        self::assertStringContainsString('Max-Age=0', $header);
    }
}
