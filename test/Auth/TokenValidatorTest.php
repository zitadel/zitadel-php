<?php

declare(strict_types=1);

namespace Zitadel\Sdk\Test\Auth;

use PHPUnit\Framework\TestCase;
use Zitadel\Sdk\Auth\Algorithm;
use Zitadel\Sdk\Auth\Claims;
use Zitadel\Sdk\Auth\JwksCache;
use Zitadel\Sdk\Auth\JwksCacheInterface;
use Zitadel\Sdk\Auth\PkceFlow;
use Zitadel\Sdk\Auth\TokenType;
use Zitadel\Sdk\Auth\TokenValidator;
use Zitadel\Sdk\Config\ZitadelConfig;

final class TokenValidatorTest extends TestCase
{
    private ZitadelConfig $config;
    private TokenValidator $validator;

    protected function setUp(): void
    {
        $this->config    = new ZitadelConfig(
            issuerUrl:    'https://example.zitadel.cloud',
            clientId:     'client-id',
            redirectUri:  'https://myapp.com/callback',
            cookieSecret: bin2hex(random_bytes(32)),
        );
        $this->validator = new TokenValidator($this->config, new JwksCache());
    }

    public function testReturnsNullForMalformedToken(): void
    {
        self::assertNull($this->validator->validate('not.a.valid.token.here'));
        self::assertNull($this->validator->validate('only.two'));
        self::assertNull($this->validator->validate(''));
        self::assertNull($this->validator->validate('one'));
    }

    /**
     * base64urlDecode uses strict: true since the fix. A token whose header or
     * payload segment contains characters outside the base64url alphabet must be
     * rejected outright — the old non-strict mode silently dropped the offending
     * bytes which could allow a crafted token to decode with different data than
     * intended (the signature check would still catch it, but we should reject
     * earlier and unconditionally).
     */
    public function testRejectsTokenWithInvalidBase64InHeader(): void
    {
        // '!' is not a valid base64url character.
        $header  = 'not!valid!base64url';
        $payload = rtrim(strtr(base64_encode((string) json_encode(['sub' => 'u'])), '+/', '-_'), '=');
        $token   = "{$header}.{$payload}.sig";

        self::assertNull($this->validator->validate($token));
    }

    public function testRejectsTokenWithInvalidBase64InPayload(): void
    {
        $header  = rtrim(strtr(base64_encode((string) json_encode(['alg' => 'RS256', 'typ' => 'JWT'])), '+/', '-_'), '=');
        $payload = 'not!valid!base64url';
        $token   = "{$header}.{$payload}.sig";

        self::assertNull($this->validator->validate($token));
    }

    public function testReturnsNullForNoneAlgorithm(): void
    {
        $header  = rtrim(strtr(base64_encode(json_encode(['alg' => 'none', 'typ' => 'JWT'])), '+/', '-_'), '=');
        $payload = rtrim(strtr(base64_encode(json_encode(['sub' => 'u', 'iss' => 'https://example.zitadel.cloud', 'exp' => time() + 3600, 'iat' => time()])), '+/', '-_'), '=');
        $token   = "{$header}.{$payload}.";

        self::assertNull($this->validator->validate($token));
    }

    public function testReturnsNullForNoneAlgorithmCaseInsensitive(): void
    {
        foreach (['NONE', 'None', 'nOnE'] as $alg) {
            $header  = rtrim(strtr(base64_encode(json_encode(['alg' => $alg, 'typ' => 'JWT'])), '+/', '-_'), '=');
            $payload = rtrim(strtr(base64_encode(json_encode(['sub' => 'u', 'iss' => 'https://example.zitadel.cloud', 'exp' => time() + 3600])), '+/', '-_'), '=');
            $token   = "{$header}.{$payload}.";

            self::assertNull($this->validator->validate($token), "alg:{$alg} should be rejected");
        }
    }

    public function testReturnsNullForMissingAlgHeader(): void
    {
        $header  = rtrim(strtr(base64_encode(json_encode(['typ' => 'JWT'])), '+/', '-_'), '=');
        $payload = rtrim(strtr(base64_encode(json_encode(['sub' => 'u', 'iss' => 'https://example.zitadel.cloud', 'exp' => time() + 3600])), '+/', '-_'), '=');
        $token   = "{$header}.{$payload}.sig";

        self::assertNull($this->validator->validate($token));
    }

    public function testReturnsNullForUnknownAlgorithm(): void
    {
        $header  = rtrim(strtr(base64_encode(json_encode(['alg' => 'HS256', 'typ' => 'JWT'])), '+/', '-_'), '=');
        $payload = rtrim(strtr(base64_encode(json_encode(['sub' => 'u', 'iss' => 'https://example.zitadel.cloud', 'exp' => time() + 3600])), '+/', '-_'), '=');
        $token   = "{$header}.{$payload}.sig";

        self::assertNull($this->validator->validate($token));
    }

    public function testReturnsNullForDisallowedAlgorithm(): void
    {
        $restrictedConfig = new ZitadelConfig(
            issuerUrl:         'https://example.zitadel.cloud',
            clientId:          'client-id',
            redirectUri:       'https://myapp.com/callback',
            cookieSecret:      bin2hex(random_bytes(32)),
            allowedAlgorithms: [Algorithm::RS256],
        );
        $validator = new TokenValidator($restrictedConfig, new JwksCache());

        $header  = rtrim(strtr(base64_encode(json_encode(['alg' => 'ES256', 'typ' => 'JWT'])), '+/', '-_'), '=');
        $payload = rtrim(strtr(base64_encode(json_encode(['sub' => 'u', 'iss' => 'https://example.zitadel.cloud', 'exp' => time() + 3600])), '+/', '-_'), '=');
        $token   = "{$header}.{$payload}.sig";

        self::assertNull($validator->validate($token));
    }

    public function testValidatesRs256TokenSuccessfully(): void
    {
        $privateKey = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);
        self::assertNotFalse($privateKey);

        $details = openssl_pkey_get_details($privateKey);
        self::assertNotFalse($details);

        $n = rtrim(strtr(base64_encode($details['rsa']['n']), '+/', '-_'), '=');
        $e = rtrim(strtr(base64_encode($details['rsa']['e']), '+/', '-_'), '=');

        $kid     = 'test-key-id';
        $now     = time();
        $header  = rtrim(strtr(base64_encode(json_encode(['alg' => 'RS256', 'typ' => 'JWT', 'kid' => $kid])), '+/', '-_'), '=');
        $payload = rtrim(strtr(base64_encode(json_encode([
            'sub' => 'user-abc',
            'iss' => 'https://example.zitadel.cloud',
            'exp' => $now + 3600,
            'iat' => $now,
            'name' => 'Test User',
            'email' => 'test@example.com',
        ])), '+/', '-_'), '=');
        $signingInput = "{$header}.{$payload}";

        openssl_sign($signingInput, $signature, $privateKey, OPENSSL_ALGO_SHA256);
        $sigEncoded = rtrim(strtr(base64_encode($signature), '+/', '-_'), '=');
        $token = "{$signingInput}.{$sigEncoded}";

        // Build a mock JwksCache that returns the public key
        $jwks = ['keys' => [['kty' => 'RSA', 'kid' => $kid, 'use' => 'sig', 'alg' => 'RS256', 'n' => $n, 'e' => $e]]];
        $mockCache = $this->buildMockCache($jwks, 'https://example.zitadel.cloud/oauth/v2/keys', $kid);

        $validator = new TokenValidator($this->config, $mockCache);
        $claims    = $validator->validate($token);

        self::assertInstanceOf(Claims::class, $claims);
        self::assertSame('user-abc', $claims->sub);
        self::assertSame('https://example.zitadel.cloud', $claims->iss);
        self::assertSame('Test User', $claims->name);
        self::assertSame('test@example.com', $claims->email);
        self::assertSame($token, $claims->token);
    }

    public function testRejectsExpiredToken(): void
    {
        $privateKey = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        self::assertNotFalse($privateKey);

        $details = openssl_pkey_get_details($privateKey);
        self::assertNotFalse($details);
        $n = rtrim(strtr(base64_encode($details['rsa']['n']), '+/', '-_'), '=');
        $e = rtrim(strtr(base64_encode($details['rsa']['e']), '+/', '-_'), '=');

        $kid     = 'test-key';
        $past    = time() - 100;
        $header  = rtrim(strtr(base64_encode(json_encode(['alg' => 'RS256', 'typ' => 'JWT', 'kid' => $kid])), '+/', '-_'), '=');
        $payload = rtrim(strtr(base64_encode(json_encode([
            'sub' => 'u',
            'iss' => 'https://example.zitadel.cloud',
            'exp' => $past,
            'iat' => $past - 60,
        ])), '+/', '-_'), '=');
        $signingInput = "{$header}.{$payload}";
        openssl_sign($signingInput, $signature, $privateKey, OPENSSL_ALGO_SHA256);
        $sigEncoded = rtrim(strtr(base64_encode($signature), '+/', '-_'), '=');
        $token = "{$signingInput}.{$sigEncoded}";

        $jwks      = ['keys' => [['kty' => 'RSA', 'kid' => $kid, 'use' => 'sig', 'alg' => 'RS256', 'n' => $n, 'e' => $e]]];
        $mockCache = $this->buildMockCache($jwks, 'https://example.zitadel.cloud/oauth/v2/keys', $kid);

        $validator = new TokenValidator($this->config, $mockCache);
        self::assertNull($validator->validate($token));
    }

    public function testRejectsWrongIssuer(): void
    {
        $privateKey = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        self::assertNotFalse($privateKey);

        $details = openssl_pkey_get_details($privateKey);
        self::assertNotFalse($details);
        $n = rtrim(strtr(base64_encode($details['rsa']['n']), '+/', '-_'), '=');
        $e = rtrim(strtr(base64_encode($details['rsa']['e']), '+/', '-_'), '=');

        $kid     = 'test-key';
        $header  = rtrim(strtr(base64_encode(json_encode(['alg' => 'RS256', 'typ' => 'JWT', 'kid' => $kid])), '+/', '-_'), '=');
        $payload = rtrim(strtr(base64_encode(json_encode([
            'sub' => 'u',
            'iss' => 'https://evil.example.com',
            'exp' => time() + 3600,
            'iat' => time(),
        ])), '+/', '-_'), '=');
        $signingInput = "{$header}.{$payload}";
        openssl_sign($signingInput, $signature, $privateKey, OPENSSL_ALGO_SHA256);
        $sigEncoded = rtrim(strtr(base64_encode($signature), '+/', '-_'), '=');
        $token = "{$signingInput}.{$sigEncoded}";

        $jwks      = ['keys' => [['kty' => 'RSA', 'kid' => $kid, 'use' => 'sig', 'alg' => 'RS256', 'n' => $n, 'e' => $e]]];
        $mockCache = $this->buildMockCache($jwks, 'https://example.zitadel.cloud/oauth/v2/keys', $kid);

        $validator = new TokenValidator($this->config, $mockCache);
        self::assertNull($validator->validate($token));
    }

    public function testValidatesEs256TokenSuccessfully(): void
    {
        [$token, $mockCache] = $this->buildEcToken('prime256v1', 'P-256', 32, 'ES256', OPENSSL_ALGO_SHA256);

        $config = new ZitadelConfig(
            issuerUrl:         'https://example.zitadel.cloud',
            clientId:          'client-id',
            redirectUri:       'https://myapp.com/callback',
            cookieSecret:      bin2hex(random_bytes(32)),
            allowedAlgorithms: [Algorithm::ES256],
        );
        self::assertInstanceOf(Claims::class, (new TokenValidator($config, $mockCache))->validate($token));
    }

    public function testValidatesEs384TokenSuccessfully(): void
    {
        [$token, $mockCache] = $this->buildEcToken('secp384r1', 'P-384', 48, 'ES384', OPENSSL_ALGO_SHA384);

        $config = new ZitadelConfig(
            issuerUrl:         'https://example.zitadel.cloud',
            clientId:          'client-id',
            redirectUri:       'https://myapp.com/callback',
            cookieSecret:      bin2hex(random_bytes(32)),
            allowedAlgorithms: [Algorithm::ES384],
        );
        self::assertInstanceOf(Claims::class, (new TokenValidator($config, $mockCache))->validate($token));
    }

    /**
     * ES512 (P-521) signatures have a DER SEQUENCE inner length > 127 bytes,
     * which exercises the asn1Length() long-form encoding added to p1363ToDer().
     */
    public function testValidatesEs512TokenSuccessfully(): void
    {
        [$token, $mockCache] = $this->buildEcToken('secp521r1', 'P-521', 66, 'ES512', OPENSSL_ALGO_SHA512);

        $config = new ZitadelConfig(
            issuerUrl:         'https://example.zitadel.cloud',
            clientId:          'client-id',
            redirectUri:       'https://myapp.com/callback',
            cookieSecret:      bin2hex(random_bytes(32)),
            allowedAlgorithms: [Algorithm::ES512],
        );
        self::assertInstanceOf(Claims::class, (new TokenValidator($config, $mockCache))->validate($token));
    }

    public function testRejectsTokenWithFutureNbf(): void
    {
        [$token, $mockCache] = $this->buildRs256Token([
            'sub' => 'u',
            'iss' => 'https://example.zitadel.cloud',
            'exp' => time() + 7200,
            'iat' => time(),
            'nbf' => time() + 3600,
        ]);

        self::assertNull((new TokenValidator($this->config, $mockCache))->validate($token));
    }

    public function testAcceptsTokenWithPastNbf(): void
    {
        [$token, $mockCache] = $this->buildRs256Token([
            'sub' => 'u',
            'iss' => 'https://example.zitadel.cloud',
            'exp' => time() + 3600,
            'iat' => time() - 60,
            'nbf' => time() - 60,
        ]);

        self::assertInstanceOf(Claims::class, (new TokenValidator($this->config, $mockCache))->validate($token));
    }

    public function testRejectsTokenWithFutureIat(): void
    {
        [$token, $mockCache] = $this->buildRs256Token([
            'sub' => 'u',
            'iss' => 'https://example.zitadel.cloud',
            'exp' => time() + 7200,
            'iat' => time() + 3600,
        ]);

        self::assertNull((new TokenValidator($this->config, $mockCache))->validate($token));
    }

    public function testRejectsTokenWithAudienceMismatch(): void
    {
        [$token, $mockCache] = $this->buildRs256Token([
            'sub' => 'u',
            'iss' => 'https://example.zitadel.cloud',
            'exp' => time() + 3600,
            'iat' => time(),
            'aud' => 'other-app',
        ]);

        $config = new ZitadelConfig(
            issuerUrl:    'https://example.zitadel.cloud',
            clientId:     'client-id',
            redirectUri:  'https://myapp.com/callback',
            cookieSecret: bin2hex(random_bytes(32)),
            audience:     'my-app',
        );
        self::assertNull((new TokenValidator($config, $mockCache))->validate($token));
    }

    public function testAcceptsTokenWithMatchingAudience(): void
    {
        [$token, $mockCache] = $this->buildRs256Token([
            'sub' => 'u',
            'iss' => 'https://example.zitadel.cloud',
            'exp' => time() + 3600,
            'iat' => time(),
            'aud' => 'my-app',
        ]);

        $config = new ZitadelConfig(
            issuerUrl:    'https://example.zitadel.cloud',
            clientId:     'client-id',
            redirectUri:  'https://myapp.com/callback',
            cookieSecret: bin2hex(random_bytes(32)),
            audience:     'my-app',
        );
        self::assertInstanceOf(Claims::class, (new TokenValidator($config, $mockCache))->validate($token));
    }

    // ---------------------------------------------------------------------------
    // typ header — at+JWT accepted, absent → rejected
    // ---------------------------------------------------------------------------

    /**
     * Zitadel issues access tokens with `typ: at+JWT` (RFC 9068). The validator
     * must accept this value because it is listed in the default allowedTokenTypes
     * alongside plain `typ: JWT`.
     */
    public function testAcceptsTokenWithAtJwtTypHeader(): void
    {
        $privateKey = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        self::assertNotFalse($privateKey);

        $details = openssl_pkey_get_details($privateKey);
        self::assertNotFalse($details);

        $n   = rtrim(strtr(base64_encode($details['rsa']['n']), '+/', '-_'), '=');
        $e   = rtrim(strtr(base64_encode($details['rsa']['e']), '+/', '-_'), '=');
        $kid = 'rsa-atjwt-key';
        $now = time();

        // Use 'at+JWT' as the typ header value.
        $header       = rtrim(strtr(base64_encode(json_encode(['alg' => 'RS256', 'typ' => 'at+JWT', 'kid' => $kid])), '+/', '-_'), '=');
        $payloadB64   = rtrim(strtr(base64_encode(json_encode([
            'sub' => 'user-atjwt',
            'iss' => 'https://example.zitadel.cloud',
            'exp' => $now + 3600,
            'iat' => $now,
        ])), '+/', '-_'), '=');
        $signingInput = "{$header}.{$payloadB64}";

        openssl_sign($signingInput, $signature, $privateKey, OPENSSL_ALGO_SHA256);
        $sigEncoded = rtrim(strtr(base64_encode($signature), '+/', '-_'), '=');
        $token = "{$signingInput}.{$sigEncoded}";

        $jwks      = ['keys' => [['kty' => 'RSA', 'kid' => $kid, 'use' => 'sig', 'alg' => 'RS256', 'n' => $n, 'e' => $e]]];
        $mockCache = $this->buildMockCache($jwks, 'https://example.zitadel.cloud/oauth/v2/keys', $kid);

        $claims = (new TokenValidator($this->config, $mockCache))->validate($token);
        self::assertInstanceOf(Claims::class, $claims);
        self::assertSame('user-atjwt', $claims->sub);
    }

    /**
     * A token with no `typ` header at all must be rejected (step 9 of the
     * validation pipeline requires a non-null `typ` that matches an allowed type).
     */
    public function testReturnsNullWhenTypHeaderAbsent(): void
    {
        $header  = rtrim(strtr(base64_encode(json_encode(['alg' => 'RS256', 'kid' => 'k'])), '+/', '-_'), '=');
        $payload = rtrim(strtr(base64_encode(json_encode([
            'sub' => 'u',
            'iss' => 'https://example.zitadel.cloud',
            'exp' => time() + 3600,
            'iat' => time(),
        ])), '+/', '-_'), '=');
        $token = "{$header}.{$payload}.fakesig";

        self::assertNull($this->validator->validate($token));
    }

    // ---------------------------------------------------------------------------
    // aud claim as JSON array
    // ---------------------------------------------------------------------------

    /**
     * The `aud` claim may be a JSON array of strings rather than a plain string.
     * When the configured audience appears anywhere in that array, the token must
     * be accepted.
     */
    public function testAcceptsAudienceClaimAsJsonArrayWithMatch(): void
    {
        [$token, $mockCache] = $this->buildRs256Token([
            'sub' => 'u',
            'iss' => 'https://example.zitadel.cloud',
            'exp' => time() + 3600,
            'iat' => time(),
            'aud' => ['other-service', 'my-app', 'yet-another'],
        ]);

        $config = new ZitadelConfig(
            issuerUrl:    'https://example.zitadel.cloud',
            clientId:     'client-id',
            redirectUri:  'https://myapp.com/callback',
            cookieSecret: bin2hex(random_bytes(32)),
            audience:     'my-app',
        );
        self::assertInstanceOf(Claims::class, (new TokenValidator($config, $mockCache))->validate($token));
    }

    /**
     * When `aud` is a JSON array and none of its entries match the configured
     * audience, the token must be rejected.
     */
    public function testRejectsAudienceClaimAsJsonArrayWithNoMatch(): void
    {
        [$token, $mockCache] = $this->buildRs256Token([
            'sub' => 'u',
            'iss' => 'https://example.zitadel.cloud',
            'exp' => time() + 3600,
            'iat' => time(),
            'aud' => ['service-a', 'service-b'],
        ]);

        $config = new ZitadelConfig(
            issuerUrl:    'https://example.zitadel.cloud',
            clientId:     'client-id',
            redirectUri:  'https://myapp.com/callback',
            cookieSecret: bin2hex(random_bytes(32)),
            audience:     'my-app',
        );
        self::assertNull((new TokenValidator($config, $mockCache))->validate($token));
    }

    /**
     * @param array<string, mixed> $claims
     * @return array{0: string, 1: \Zitadel\Sdk\Auth\JwksCacheInterface}
     */
    private function buildRs256Token(array $claims): array
    {
        $privateKey = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        self::assertNotFalse($privateKey);

        $details = openssl_pkey_get_details($privateKey);
        self::assertNotFalse($details);

        $n   = rtrim(strtr(base64_encode($details['rsa']['n']), '+/', '-_'), '=');
        $e   = rtrim(strtr(base64_encode($details['rsa']['e']), '+/', '-_'), '=');
        $kid = 'rsa-test-key';

        $header       = rtrim(strtr(base64_encode(json_encode(['alg' => 'RS256', 'typ' => 'JWT', 'kid' => $kid])), '+/', '-_'), '=');
        $payloadB64   = rtrim(strtr(base64_encode(json_encode($claims)), '+/', '-_'), '=');
        $signingInput = "{$header}.{$payloadB64}";

        openssl_sign($signingInput, $signature, $privateKey, OPENSSL_ALGO_SHA256);
        $sigEncoded = rtrim(strtr(base64_encode($signature), '+/', '-_'), '=');
        $token      = "{$signingInput}.{$sigEncoded}";

        $jwks      = ['keys' => [['kty' => 'RSA', 'kid' => $kid, 'use' => 'sig', 'alg' => 'RS256', 'n' => $n, 'e' => $e]]];
        $mockCache = $this->buildMockCache($jwks, 'https://example.zitadel.cloud/oauth/v2/keys', $kid);

        return [$token, $mockCache];
    }

    /**
     * Builds a signed EC JWT. openssl_sign() produces a DER signature; JWT/Zitadel
     * uses IEEE P1363 (r||s), so the signature is converted before embedding.
     *
     * @return array{0: string, 1: \Zitadel\Sdk\Auth\JwksCacheInterface}
     */
    private function buildEcToken(
        string $curveName,
        string $crv,
        int $curveBytes,
        string $alg,
        int $opensslAlgo,
    ): array {
        $privateKey = openssl_pkey_new(['curve_name' => $curveName, 'private_key_type' => OPENSSL_KEYTYPE_EC]);
        self::assertNotFalse($privateKey);

        $details = openssl_pkey_get_details($privateKey);
        self::assertNotFalse($details);

        // Pad to the full field width — PHP's BN2bin may strip leading zeros
        // (critical for P-521 where the MSByte is 0x00 ~50% of the time).
        $x   = rtrim(strtr(base64_encode(str_pad($details['ec']['x'], $curveBytes, "\x00", STR_PAD_LEFT)), '+/', '-_'), '=');
        $y   = rtrim(strtr(base64_encode(str_pad($details['ec']['y'], $curveBytes, "\x00", STR_PAD_LEFT)), '+/', '-_'), '=');
        $kid = "ec-key-{$crv}";
        $now = time();

        $header       = rtrim(strtr(base64_encode(json_encode(['alg' => $alg, 'typ' => 'JWT', 'kid' => $kid])), '+/', '-_'), '=');
        $payloadB64   = rtrim(strtr(base64_encode(json_encode([
            'sub' => 'user-ec',
            'iss' => 'https://example.zitadel.cloud',
            'exp' => $now + 3600,
            'iat' => $now,
        ])), '+/', '-_'), '=');
        $signingInput = "{$header}.{$payloadB64}";

        openssl_sign($signingInput, $derSig, $privateKey, $opensslAlgo);

        $p1363Sig   = self::derToP1363($derSig, $curveBytes);
        $sigEncoded = rtrim(strtr(base64_encode($p1363Sig), '+/', '-_'), '=');
        $token      = "{$signingInput}.{$sigEncoded}";

        $jwks      = ['keys' => [['kty' => 'EC', 'kid' => $kid, 'use' => 'sig', 'alg' => $alg, 'crv' => $crv, 'x' => $x, 'y' => $y]]];
        $mockCache = $this->buildMockCache($jwks, 'https://example.zitadel.cloud/oauth/v2/keys', $kid);

        return [$token, $mockCache];
    }

    /**
     * Converts a DER-encoded EC signature to IEEE P1363 format (r||s).
     *
     * This is the inverse of TokenValidator::p1363ToDer() and is required here
     * because openssl_sign() outputs DER, but JWT signatures must be P1363.
     */
    private static function derToP1363(string $der, int $curveBytes): string
    {
        $pos = 1; // skip \x30 SEQUENCE tag

        // Skip sequence length (short or long form)
        $seqLen = ord($der[$pos++]);
        if ($seqLen & 0x80) {
            $pos += $seqLen & 0x7f;
        }

        // Read r INTEGER
        $pos++;
        $rLen = ord($der[$pos++]);
        $r    = substr($der, $pos, $rLen);
        $pos += $rLen;

        // Read s INTEGER
        $pos++;
        $sLen = ord($der[$pos++]);
        $s    = substr($der, $pos, $sLen);

        // Strip the leading \x00 that DER adds to keep the integer positive
        if (strlen($r) > $curveBytes && $r[0] === "\x00") {
            $r = substr($r, 1);
        }
        if (strlen($s) > $curveBytes && $s[0] === "\x00") {
            $s = substr($s, 1);
        }

        return str_pad($r, $curveBytes, "\x00", STR_PAD_LEFT)
            . str_pad($s, $curveBytes, "\x00", STR_PAD_LEFT);
    }

    /**
     * @param array<string, mixed> $jwks
     */
    private function buildMockCache(array $jwks, string $expectedUri, ?string $kid): \Zitadel\Sdk\Auth\JwksCacheInterface
    {
        /** @var array<array<string, mixed>> $keyList */
        $keyList = $jwks['keys'] ?? [];

        $keys = array_filter($keyList, static function (array $key) use ($kid): bool {
            if (($key['use'] ?? '') !== 'sig') {
                return false;
            }
            return $kid === null || ($key['kid'] ?? null) === $kid;
        });

        $matchedKey = array_values($keys)[0] ?? null;
        $openSslKey = null;

        if ($matchedKey !== null) {
            try {
                $openSslKey = \Zitadel\Sdk\Auth\JwkConverter::toKey($matchedKey);
            } catch (\InvalidArgumentException) {
                $openSslKey = null;
            }
        }

        return new class ($openSslKey) implements \Zitadel\Sdk\Auth\JwksCacheInterface {
            public function __construct(private readonly ?\OpenSSLAsymmetricKey $key)
            {
            }

            #[\Override]
            public function getPublicKey(
                string $jwksUri,
                ?string $kid,
                string $alg,
                int $ttlSeconds,
                int $timeoutSeconds,
            ): ?\OpenSSLAsymmetricKey {
                return $this->key;
            }

            #[\Override]
            public function clearCache(): void
            {
            }
        };
    }
}
