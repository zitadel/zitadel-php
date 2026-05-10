<?php

declare(strict_types=1);

namespace Zitadel\Sdk\Auth;

/**
 * Converts a JSON Web Key (JWK) to an OpenSSL public key resource.
 *
 * Handles RSA and EC keys using only `ext-openssl` — no external dependencies.
 * RSA keys are reconstructed from the `n` and `e` parameters via ASN.1 DER.
 * EC keys are reconstructed from `x`, `y`, and `crv` via DER with named-curve OIDs.
 *
 * Supported curves: P-256 (`1.2.840.10045.3.1.7`), P-384 (`1.3.132.0.34`),
 * P-521 (`1.3.132.0.35`).
 */
final class JwkConverter
{
    private function __construct()
    {
    }

    private const array CURVE_OIDS = [
        'P-256' => "\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07",
        'P-384' => "\x06\x05\x2b\x81\x04\x00\x22",
        'P-521' => "\x06\x05\x2b\x81\x04\x00\x23",
    ];

    /**
     * Required byte-length for each curve's coordinate components.
     *
     * RFC 7517 §6.2.1.2/6.2.1.3: "The length of this octet string MUST be the
     * full size of a coordinate for the curve specified in the 'crv' parameter."
     * P-521 coordinates are 66 bytes (ceil(521/8)), but PHP's BN2bin strips
     * leading zero bytes, so the raw value may arrive as 65 bytes; we pad here.
     *
     * @var array<string, int>
     */
    private const array CURVE_FIELD_SIZES = [
        'P-256' => 32,
        'P-384' => 48,
        'P-521' => 66,
    ];

    /**
     * Converts a single JWK array to an OpenSSL public key.
     *
     * @param array<string, string> $jwk Decoded JWK object.
     * @return \OpenSSLAsymmetricKey
     * @throws \InvalidArgumentException When the JWK is invalid or unsupported.
     */
    public static function toKey(array $jwk): \OpenSSLAsymmetricKey
    {
        $kty = $jwk['kty'] ?? '';

        if ($kty === 'RSA') {
            return self::rsaToKey($jwk);
        }

        if ($kty === 'EC') {
            return self::ecToKey($jwk);
        }

        throw new \InvalidArgumentException("[zitadel] Unsupported JWK key type: {$kty}");
    }

    /**
     * Converts an RSA JWK (`"kty": "RSA"`) to an OpenSSL public key resource.
     *
     * @param array<string, string> $jwk The JWK object; must contain `n` (modulus) and `e` (exponent).
     * @return \OpenSSLAsymmetricKey The parsed RSA public key.
     * @throws \InvalidArgumentException If required fields are missing or the key cannot be parsed.
     */
    private static function rsaToKey(array $jwk): \OpenSSLAsymmetricKey
    {
        if (!isset($jwk['n'], $jwk['e'])) {
            throw new \InvalidArgumentException('[zitadel] RSA JWK missing required fields n and/or e.');
        }

        $n = self::base64urlDecode($jwk['n']);
        $e = self::base64urlDecode($jwk['e']);

        $nDer = self::encodeInteger($n);
        $eDer = self::encodeInteger($e);

        $seq        = self::encodeSequence($nDer . $eDer);
        $algId      = self::encodeSequence("\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00");
        $bitString  = "\x03" . self::encodeLength(strlen($seq) + 1) . "\x00" . $seq;
        $spki       = self::encodeSequence($algId . $bitString);

        $pem = "-----BEGIN PUBLIC KEY-----\n" .
            chunk_split(base64_encode($spki), 64, "\n") .
            "-----END PUBLIC KEY-----\n";

        $key = openssl_pkey_get_public($pem);
        if ($key === false) {
            throw new \InvalidArgumentException('[zitadel] Failed to parse RSA public key from JWK.');
        }

        return $key;
    }

    /**
     * Converts an EC JWK (`"kty": "EC"`) to an OpenSSL public key resource.
     *
     * Supports P-256 (`crv: P-256`), P-384 (`crv: P-384`), and P-521 (`crv: P-521`) curves.
     *
     * @param array<string, string> $jwk The JWK object; must contain `x`, `y` (coordinates), and `crv` (curve name).
     * @return \OpenSSLAsymmetricKey The parsed EC public key.
     * @throws \InvalidArgumentException If required fields are missing, the curve is unsupported, or the key cannot be parsed.
     */
    private static function ecToKey(array $jwk): \OpenSSLAsymmetricKey
    {
        if (!isset($jwk['x'], $jwk['y'], $jwk['crv'])) {
            throw new \InvalidArgumentException('[zitadel] EC JWK missing required fields x, y, and/or crv.');
        }

        $curveOid = self::CURVE_OIDS[$jwk['crv']] ?? null;
        if ($curveOid === null) {
            throw new \InvalidArgumentException("[zitadel] Unsupported EC curve: {$jwk['crv']}");
        }

        $fieldSize = self::CURVE_FIELD_SIZES[$jwk['crv']];
        $x         = str_pad(self::base64urlDecode($jwk['x']), $fieldSize, "\x00", STR_PAD_LEFT);
        $y         = str_pad(self::base64urlDecode($jwk['y']), $fieldSize, "\x00", STR_PAD_LEFT);

        $point     = "\x04" . $x . $y;
        $algOid    = "\x06\x07\x2a\x86\x48\xce\x3d\x02\x01";
        $algId     = self::encodeSequence($algOid . $curveOid);
        $bitString = "\x03" . self::encodeLength(strlen($point) + 1) . "\x00" . $point;
        $spki      = self::encodeSequence($algId . $bitString);

        $pem = "-----BEGIN PUBLIC KEY-----\n" .
            chunk_split(base64_encode($spki), 64, "\n") .
            "-----END PUBLIC KEY-----\n";

        $key = openssl_pkey_get_public($pem);
        if ($key === false) {
            throw new \InvalidArgumentException('[zitadel] Failed to parse EC public key from JWK.');
        }

        return $key;
    }

    /**
     * Decodes a base64url-encoded string into raw binary.
     *
     * @param string $input Base64url-encoded value (no padding required).
     * @return string Decoded binary string.
     * @throws \InvalidArgumentException If the input is not valid base64url.
     */
    private static function base64urlDecode(string $input): string
    {
        $padded = strtr($input, '-_', '+/') . str_repeat('=', (4 - strlen($input) % 4) % 4);
        $result = base64_decode($padded);
        if ($result === false) {
            throw new \InvalidArgumentException('[zitadel] Invalid base64url encoding in JWK.');
        }

        return $result;
    }

    /**
     * Encodes a binary integer value as a DER INTEGER element (tag `0x02`).
     *
     * Prepends a zero byte when the high bit is set to ensure the value is
     * interpreted as a positive integer by ASN.1 decoders.
     *
     * @param string $bytes Raw big-endian binary integer value.
     * @return string DER-encoded INTEGER element.
     */
    private static function encodeInteger(string $bytes): string
    {
        if (ord($bytes[0]) >= 0x80) {
            $bytes = "\x00" . $bytes;
        }

        return "\x02" . self::encodeLength(strlen($bytes)) . $bytes;
    }

    /**
     * Encodes the given content as a DER SEQUENCE element (tag `0x30`).
     *
     * @param string $content Pre-encoded DER content to wrap in the SEQUENCE.
     * @return string DER-encoded SEQUENCE element.
     */
    private static function encodeSequence(string $content): string
    {
        return "\x30" . self::encodeLength(strlen($content)) . $content;
    }

    /**
     * Encodes an ASN.1 length value in DER format.
     *
     * Uses short-form encoding (single byte) for lengths below 128, and
     * long-form encoding for larger values.
     *
     * @param int $len The length to encode (non-negative).
     * @return string DER-encoded length bytes.
     */
    private static function encodeLength(int $len): string
    {
        if ($len < 0x80) {
            return chr($len);
        }

        $bytes = '';
        $tmp   = $len;
        while ($tmp > 0) {
            $bytes = chr($tmp & 0xff) . $bytes;
            $tmp >>= 8;
        }

        return chr(0x80 | strlen($bytes)) . $bytes;
    }
}
