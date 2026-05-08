<?php

declare(strict_types=1);

namespace Zitadel\Sdk\Auth;

use Zitadel\Sdk\Config\ZitadelConfig;

/**
 * Validates a JWT access token and returns its decoded claims.
 *
 * Validation order (18 steps):
 *
 *  1. Split at `.` — exactly 3 segments required (rejects JWE 5-segment tokens)
 *  2. Base64url-decode header — `=== false` guard
 *  3. Base64url-decode payload — `=== false` guard
 *  4. `json_validate()` + `json_decode()` header; same for payload
 *  5. Require `alg` field present in header — missing → null
 *  6. Reject `alg: none` unconditionally (case-insensitive, before JWKS fetch)
 *  7. Map `alg` to {@see Algorithm} via `tryFrom` — unknown → null
 *  8. Reject if algorithm not in {@see ZitadelConfig::$allowedAlgorithms}
 *  9. Validate `typ` header (case-insensitive) against {@see ZitadelConfig::$allowedTokenTypes}
 * 10. Fetch public key via {@see JwksCache::getPublicKey()} (filters `"use":"sig"`) — null → null
 * 11. Verify signature with {@see openssl_verify()}. EC: convert IEEE P1363 → DER first
 * 12. Validate `iss` with strict string equality against {@see ZitadelConfig::$issuerUrl}
 * 13. Validate `aud` if {@see ZitadelConfig::$audience} is set
 * 14. Validate `exp` (must be in the future, minus clock skew)
 * 15. Validate `nbf` if present (must be in the past, plus clock skew)
 * 16. Validate `iat` if present (must not be in the future, plus clock skew)
 * 17. Require `sub` present and non-empty
 * 18. Return {@see Claims} (including `$token` = raw signed JWT). Any failure → null; never throws
 */
readonly class TokenValidator
{
    /**
     * @param ZitadelConfig        $config Configuration for issuer, algorithms, audience, etc.
     * @param JwksCacheInterface   $cache  Shared JWKS key cache (typically a singleton).
     */
    public function __construct(
        private ZitadelConfig      $config,
        private JwksCacheInterface $cache,
    ) {
    }

    /**
     * Validates the token and returns its claims.
     *
     * Returns null on any validation failure — expired token, bad signature,
     * wrong issuer, missing key, etc. Never throws.
     *
     * @param string $token Raw JWT string (three base64url segments joined by `.`).
     * @return Claims|null Decoded claims on success; null on any failure.
     */
    public function validate(#[\SensitiveParameter] string $token): ?Claims
    {
        // Step 1 — exactly 3 segments
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            return null;
        }

        [$headerB64, $payloadB64, $sigB64] = $parts;

        // Steps 2–3 — base64url decode
        $headerJson  = self::base64urlDecode($headerB64);
        $payloadJson = self::base64urlDecode($payloadB64);

        // Step 4 — json_validate + json_decode header and payload
        if (!json_validate($headerJson) || !json_validate($payloadJson)) {
            return null;
        }

        /** @var array<string, mixed>|null $header */
        $header = json_decode($headerJson, true);
        /** @var array<string, mixed>|null $payload */
        $payload = json_decode($payloadJson, true);

        if (!is_array($header) || !is_array($payload)) {
            return null;
        }

        // Step 5 — alg field must be present
        if (!isset($header['alg']) || !is_string($header['alg'])) {
            return null;
        }

        $algStr = $header['alg'];

        // Step 6 — reject alg:none unconditionally
        if (strtolower($algStr) === 'none') {
            return null;
        }

        // Step 7 — map to Algorithm enum
        $algorithm = Algorithm::tryFrom($algStr);
        if ($algorithm === null) {
            return null;
        }

        // Step 8 — check against allowedAlgorithms
        if (!in_array($algorithm, $this->config->allowedAlgorithms, true)) {
            return null;
        }

        // Step 9 — validate typ (case-insensitive)
        $typ = isset($header['typ']) ? strtolower((string) $header['typ']) : null;
        $allowed = array_map(
            static fn (TokenType $t): string => strtolower($t->value),
            $this->config->allowedTokenTypes
        );
        if ($typ === null || !in_array($typ, $allowed, true)) {
            return null;
        }

        // Step 10 — fetch public key
        $kid = isset($header['kid']) && is_string($header['kid']) ? $header['kid'] : null;
        $key = $this->cache->getPublicKey(
            $this->config->jwksUri(),
            $kid,
            $algStr,
            $this->config->jwksTtlSeconds,
            $this->config->httpTimeoutSeconds,
        );

        if ($key === null) {
            return null;
        }

        // Step 11 — verify signature
        $signedInput = $headerB64 . '.' . $payloadB64;
        $signature   = self::base64urlDecodeRaw($sigB64);

        if ($algorithm->isEc()) {
            $signature = self::p1363ToDer($signature);
            if ($signature === null) {
                return null;
            }
        }

        $verified = openssl_verify($signedInput, $signature, $key, $algorithm->opensslAlgo());
        if ($verified !== 1) {
            return null;
        }

        // Step 12 — iss strict equality
        if (($payload['iss'] ?? null) !== $this->config->issuerUrl) {
            return null;
        }

        // Step 13 — aud check
        if ($this->config->audience !== null) {
            $tokenAud = $payload['aud'] ?? null;
            $expected = (array) $this->config->audience;
            $actual   = is_array($tokenAud) ? $tokenAud : [$tokenAud];
            if (count(array_intersect($expected, $actual)) === 0) {
                return null;
            }
        }

        $now  = time();
        $skew = $this->config->clockSkewSeconds;

        // Step 14 — exp
        $exp = $payload['exp'] ?? null;
        if (!is_int($exp) || $now > ($exp + $skew)) {
            return null;
        }

        // Step 15 — nbf
        if (isset($payload['nbf'])) {
            $nbf = $payload['nbf'];
            if (is_int($nbf) && $now < ($nbf - $skew)) {
                return null;
            }
        }

        // Step 16 — iat
        if (isset($payload['iat'])) {
            $iat = $payload['iat'];
            if (is_int($iat) && $now < ($iat - $skew)) {
                return null;
            }
        }

        // Step 17 — sub
        $sub = $payload['sub'] ?? null;
        if (!is_string($sub) || $sub === '') {
            return null;
        }

        // Step 18 — return Claims
        return new Claims(
            sub:        $sub,
            iss:        (string) $payload['iss'],
            exp:        $exp,
            token:      $token,
            name:       isset($payload['name']) && is_string($payload['name']) ? $payload['name'] : null,
            email:      isset($payload['email']) && is_string($payload['email']) ? $payload['email'] : null,
            givenName:  isset($payload['given_name']) && is_string($payload['given_name']) ? $payload['given_name'] : null,
            familyName: isset($payload['family_name']) && is_string($payload['family_name']) ? $payload['family_name'] : null,
            payload:    $payload,
        );
    }

    private static function base64urlDecode(string $input): string
    {
        return (string) base64_decode(
            strtr($input, '-_', '+/') . str_repeat('=', (4 - strlen($input) % 4) % 4),
            strict: false
        );
    }

    private static function base64urlDecodeRaw(string $input): string
    {
        return self::base64urlDecode($input);
    }

    /**
     * Converts an IEEE P1363 EC signature (r||s) to DER-encoded ASN.1.
     *
     * P1363 format: two fixed-length big-endian integers concatenated.
     * DER format: SEQUENCE { INTEGER r, INTEGER s }
     */
    private static function p1363ToDer(string $sig): ?string
    {
        $len = strlen($sig);
        if ($len % 2 !== 0) {
            return null;
        }

        $half = $len / 2;
        $r    = ltrim(substr($sig, 0, $half), "\x00");
        $s    = ltrim(substr($sig, $half), "\x00");

        if ($r === '') {
            $r = "\x00";
        }
        if ($s === '') {
            $s = "\x00";
        }

        // Prepend 0x00 if high bit set (to keep it positive in DER)
        if (ord($r[0]) >= 0x80) {
            $r = "\x00" . $r;
        }
        if (ord($s[0]) >= 0x80) {
            $s = "\x00" . $s;
        }

        $rDer  = "\x02" . chr(strlen($r)) . $r;
        $sDer  = "\x02" . chr(strlen($s)) . $s;
        $inner = $rDer . $sDer;

        return "\x30" . chr(strlen($inner)) . $inner;
    }
}
