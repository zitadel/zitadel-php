<?php

declare(strict_types=1);

namespace Zitadel\Sdk\Test\Auth;

use PHPUnit\Framework\TestCase;
use Zitadel\Sdk\Auth\JwkConverter;

final class JwkConverterTest extends TestCase
{
    public function testConvertsRsaJwk(): void
    {
        $rsaKey = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        self::assertNotFalse($rsaKey);

        $details = openssl_pkey_get_details($rsaKey);
        self::assertNotFalse($details);

        $n = rtrim(strtr(base64_encode($details['rsa']['n']), '+/', '-_'), '=');
        $e = rtrim(strtr(base64_encode($details['rsa']['e']), '+/', '-_'), '=');

        $jwk = ['kty' => 'RSA', 'n' => $n, 'e' => $e];
        $key = JwkConverter::toKey($jwk);

        self::assertInstanceOf(\OpenSSLAsymmetricKey::class, $key);
    }

    public function testConvertsEcP256Jwk(): void
    {
        $ecKey = openssl_pkey_new(['curve_name' => 'prime256v1', 'private_key_type' => OPENSSL_KEYTYPE_EC]);
        self::assertNotFalse($ecKey);

        $details = openssl_pkey_get_details($ecKey);
        self::assertNotFalse($details);

        $x = rtrim(strtr(base64_encode($details['ec']['x']), '+/', '-_'), '=');
        $y = rtrim(strtr(base64_encode($details['ec']['y']), '+/', '-_'), '=');

        $jwk = ['kty' => 'EC', 'crv' => 'P-256', 'x' => $x, 'y' => $y];
        $key = JwkConverter::toKey($jwk);

        self::assertInstanceOf(\OpenSSLAsymmetricKey::class, $key);
    }

    public function testConvertsEcP384Jwk(): void
    {
        $ecKey = openssl_pkey_new(['curve_name' => 'secp384r1', 'private_key_type' => OPENSSL_KEYTYPE_EC]);
        self::assertNotFalse($ecKey);

        $details = openssl_pkey_get_details($ecKey);
        self::assertNotFalse($details);

        $x = rtrim(strtr(base64_encode(str_pad($details['ec']['x'], 48, "\x00", STR_PAD_LEFT)), '+/', '-_'), '=');
        $y = rtrim(strtr(base64_encode(str_pad($details['ec']['y'], 48, "\x00", STR_PAD_LEFT)), '+/', '-_'), '=');

        self::assertInstanceOf(\OpenSSLAsymmetricKey::class, JwkConverter::toKey(['kty' => 'EC', 'crv' => 'P-384', 'x' => $x, 'y' => $y]));
    }

    public function testConvertsEcP521Jwk(): void
    {
        $ecKey = openssl_pkey_new(['curve_name' => 'secp521r1', 'private_key_type' => OPENSSL_KEYTYPE_EC]);
        self::assertNotFalse($ecKey);

        $details = openssl_pkey_get_details($ecKey);
        self::assertNotFalse($details);

        // P-521 coordinates are 66 bytes (ceil(521/8)) but PHP's BN2bin strips
        // leading zero bytes — the MSByte is 0x00 roughly 50% of the time.
        $x = rtrim(strtr(base64_encode(str_pad($details['ec']['x'], 66, "\x00", STR_PAD_LEFT)), '+/', '-_'), '=');
        $y = rtrim(strtr(base64_encode(str_pad($details['ec']['y'], 66, "\x00", STR_PAD_LEFT)), '+/', '-_'), '=');

        self::assertInstanceOf(\OpenSSLAsymmetricKey::class, JwkConverter::toKey(['kty' => 'EC', 'crv' => 'P-521', 'x' => $x, 'y' => $y]));
    }

    public function testThrowsForMissingKty(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        JwkConverter::toKey([]);
    }

    public function testThrowsForUnsupportedKty(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        JwkConverter::toKey(['kty' => 'oct', 'k' => 'somekey']);
    }

    public function testThrowsForMissingRsaParameters(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        JwkConverter::toKey(['kty' => 'RSA', 'n' => 'abc123']);
    }

    public function testThrowsForMissingEcParameters(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        JwkConverter::toKey(['kty' => 'EC', 'crv' => 'P-256', 'x' => 'abc123']);
    }

    /**
     * A JWK with an empty `n` field decodes to a zero-length byte string.
     * Before the fix, encodeInteger() would call ord($bytes[0]) on an empty
     * string, producing an undefined-offset warning and unpredictable output.
     * The guard must throw InvalidArgumentException before that access.
     */
    public function testThrowsForEmptyRsaModulus(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        // base64url('') == '' — decodes to an empty byte string
        JwkConverter::toKey(['kty' => 'RSA', 'n' => '', 'e' => 'AQAB']);
    }

    public function testThrowsForEmptyRsaExponent(): void
    {
        // A real n from a fresh key, but an empty exponent — same guard path.
        $rsaKey = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        self::assertNotFalse($rsaKey);
        $details = openssl_pkey_get_details($rsaKey);
        self::assertNotFalse($details);
        $n = rtrim(strtr(base64_encode($details['rsa']['n']), '+/', '-_'), '=');

        $this->expectException(\InvalidArgumentException::class);
        JwkConverter::toKey(['kty' => 'RSA', 'n' => $n, 'e' => '']);
    }
}
