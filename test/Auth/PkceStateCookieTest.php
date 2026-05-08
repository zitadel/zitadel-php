<?php

declare(strict_types=1);

namespace Zitadel\Sdk\Test\Auth;

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
}
