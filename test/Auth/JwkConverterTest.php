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
}
