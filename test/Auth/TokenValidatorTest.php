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

    // ---------------------------------------------------------------------------
    // aud type-confusion — non-string aud values must not match via loose ==
    // ---------------------------------------------------------------------------

    /**
     * array_intersect() uses loose (==) comparison. A token whose `aud` is an
     * integer 0 must NOT satisfy an audience requirement of '0' (the string), even
     * though PHP's `0 == '0'` is true. Filtering aud entries to strings only
     * before intersection prevents this.
     */
    public function testRejectsAudIntZeroWhenAudienceIsStringZero(): void
    {
        [$token, $mockCache] = $this->buildRs256Token([
            'sub' => 'u',
            'iss' => 'https://example.zitadel.cloud',
            'exp' => time() + 3600,
            'iat' => time(),
            'aud' => 0, // integer — malformed but crafted by attacker
        ]);

        $config = new ZitadelConfig(
            issuerUrl:    'https://example.zitadel.cloud',
            clientId:     'client-id',
            redirectUri:  'https://myapp.com/callback',
            cookieSecret: bin2hex(random_bytes(32)),
            audience:     '0',
        );
        self::assertNull((new TokenValidator($config, $mockCache))->validate($token));
    }

    /**
     * A missing `aud` claim results in `[null]` during the intersection check.
     * `null == ''` is true in PHP, so a loosely-compared intersection of [''] and
     * [null] would incorrectly succeed. The string-only filter must block this.
     */
    public function testRejectsMissingAudWhenAudienceIsEmptyString(): void
    {
        [$token, $mockCache] = $this->buildRs256Token([
            'sub' => 'u',
            'iss' => 'https://example.zitadel.cloud',
            'exp' => time() + 3600,
            'iat' => time(),
            // no 'aud' key — missing claim
        ]);

        $config = new ZitadelConfig(
            issuerUrl:    'https://example.zitadel.cloud',
            clientId:     'client-id',
            redirectUri:  'https://myapp.com/callback',
            cookieSecret: bin2hex(random_bytes(32)),
            audience:     '',
        );
        self::assertNull((new TokenValidator($config, $mockCache))->validate($token));
    }

    /**
     * A non-integer `nbf` claim must cause the token to be rejected — silently
     * ignoring a non-integer `nbf` would allow an attacker to bypass the
     * not-before check by supplying a string value.
     */
    public function testRejectsTokenWithNonIntegerNbf(): void
    {
        [$token, $mockCache] = $this->buildRs256Token([
            'sub' => 'u',
            'iss' => 'https://example.zitadel.cloud',
            'exp' => time() + 3600,
            'iat' => time(),
            'nbf' => 'not-a-number',
        ]);

        self::assertNull((new TokenValidator($this->config, $mockCache))->validate($token));
    }

    /**
     * A non-integer `iat` claim must cause the token to be rejected — silently
     * ignoring a non-integer `iat` would allow an attacker to bypass the
     * issued-at check by supplying a string value.
     */
    public function testRejectsTokenWithNonIntegerIat(): void
    {
        [$token, $mockCache] = $this->buildRs256Token([
            'sub' => 'u',
            'iss' => 'https://example.zitadel.cloud',
            'exp' => time() + 3600,
            'iat' => 'not-a-number',
        ]);

        self::assertNull((new TokenValidator($this->config, $mockCache))->validate($token));
    }

    /**
     * When the `name` claim in the JWT payload is not a string (e.g. an integer),
     * the validator must coerce it to null rather than returning a wrong type.
     */
    public function testNameClaimCoercedToNullWhenNotString(): void
    {
        [$token, $mockCache] = $this->buildRs256Token([
            'sub'  => 'u',
            'iss'  => 'https://example.zitadel.cloud',
            'exp'  => time() + 3600,
            'iat'  => time(),
            'name' => 123,
        ]);

        $claims = (new TokenValidator($this->config, $mockCache))->validate($token);
        self::assertInstanceOf(Claims::class, $claims);
        self::assertNull($claims->name);
    }

    /**
     * When the `email` claim in the JWT payload is not a string (e.g. a boolean),
     * the validator must coerce it to null rather than returning a wrong type.
     */
    public function testEmailClaimCoercedToNullWhenNotString(): void
    {
        [$token, $mockCache] = $this->buildRs256Token([
            'sub'   => 'u',
            'iss'   => 'https://example.zitadel.cloud',
            'exp'   => time() + 3600,
            'iat'   => time(),
            'email' => true,
        ]);

        $claims = (new TokenValidator($this->config, $mockCache))->validate($token);
        self::assertInstanceOf(Claims::class, $claims);
        self::assertNull($claims->email);
    }

    // ---------------------------------------------------------------------------
    // Step 10 — getPublicKey returns null (no matching key available)
    // ---------------------------------------------------------------------------

    /**
     * When the JWKS cache (or a failed fetch with no stale fallback) returns null,
     * the validator must reject the token at step 10 rather than trying to verify
     * a signature with a null key.
     */
    public function testReturnsNullWhenPublicKeyIsNotAvailable(): void
    {
        // Build a syntactically valid, correctly signed token, but hand the
        // validator a cache stub that always returns null — simulating a JWKS
        // endpoint that is unreachable with no stale key cached yet.
        [$token, ] = $this->buildRs256Token([
            'sub' => 'u',
            'iss' => 'https://example.zitadel.cloud',
            'exp' => time() + 3600,
            'iat' => time(),
        ]);

        $nullCache = new class () implements \Zitadel\Sdk\Auth\JwksCacheInterface {
            #[\Override]
            public function getPublicKey(
                string $jwksUri,
                ?string $kid,
                string $alg,
                int $ttlSeconds,
                int $timeoutSeconds,
            ): ?\OpenSSLAsymmetricKey {
                return null;
            }

            #[\Override]
            public function clearCache(): void
            {
            }
        };

        self::assertNull((new TokenValidator($this->config, $nullCache))->validate($token));
    }

    // ---------------------------------------------------------------------------
    // Step 17 — sub claim empty string
    // ---------------------------------------------------------------------------

    /**
     * A token whose `sub` claim is an empty string must be rejected.
     * An empty subject provides no identity information and would cause any
     * downstream code that keys on the subject to behave incorrectly.
     */
    public function testReturnsNullForEmptySub(): void
    {
        [$token, $mockCache] = $this->buildRs256Token([
            'sub' => '',
            'iss' => 'https://example.zitadel.cloud',
            'exp' => time() + 3600,
            'iat' => time(),
        ]);

        self::assertNull((new TokenValidator($this->config, $mockCache))->validate($token));
    }

    /**
     * A token whose `sub` claim is missing entirely must be rejected.
     */
    public function testReturnsNullForMissingSub(): void
    {
        [$token, $mockCache] = $this->buildRs256Token([
            'iss' => 'https://example.zitadel.cloud',
            'exp' => time() + 3600,
            'iat' => time(),
        ]);

        self::assertNull((new TokenValidator($this->config, $mockCache))->validate($token));
    }

    /**
     * A `sub` claim that is only whitespace (e.g. "   ") conveys no identity and
     * must be rejected. The empty-string check `$sub === ''` is insufficient because
     * whitespace characters are not the empty string; `trim($sub) === ''` is required.
     */
    public function testReturnsNullForWhitespaceOnlySub(): void
    {
        foreach ([' ', '   ', "\t", "\n", " \t\n"] as $sub) {
            [$token, $mockCache] = $this->buildRs256Token([
                'sub' => $sub,
                'iss' => 'https://example.zitadel.cloud',
                'exp' => time() + 3600,
                'iat' => time(),
            ]);

            self::assertNull(
                (new TokenValidator($this->config, $mockCache))->validate($token),
                "sub={$sub} (whitespace-only) should be rejected",
            );
        }
    }

    // ---------------------------------------------------------------------------
    // alg: none bypass variants (attack patterns 1 & 2)
    // ---------------------------------------------------------------------------

    /**
     * `alg: "None"` (mixed case) must be caught by the case-insensitive none check
     * at step 6. This is already covered by testReturnsNullForNoneAlgorithmCaseInsensitive()
     * but is confirmed explicitly here for documentation purposes.
     */
    public function testRejectsNoneAlgorithmMixedCase(): void
    {
        $header  = rtrim(strtr(base64_encode(json_encode(['alg' => 'None', 'typ' => 'JWT'])), '+/', '-_'), '=');
        $payload = rtrim(strtr(base64_encode(json_encode(['sub' => 'u', 'iss' => 'https://example.zitadel.cloud', 'exp' => time() + 3600])), '+/', '-_'), '=');
        $token   = "{$header}.{$payload}.";

        self::assertNull($this->validator->validate($token));
    }

    /**
     * `alg: " none "` (with surrounding whitespace) must be rejected at step 6.
     *
     * Without trim(), strtolower(' none ') === 'none' is false, so the none check
     * is silently skipped. Step 7 (Algorithm::tryFrom) would still reject it because
     * no enum case matches ' none ', but that ordering dependency is fragile. The
     * trim() fix ensures the none check itself catches it unconditionally.
     */
    public function testRejectsNoneAlgorithmWithSurroundingSpaces(): void
    {
        foreach ([' none', 'none ', ' none ', " NONE\t"] as $alg) {
            $header  = rtrim(strtr(base64_encode(json_encode(['alg' => $alg, 'typ' => 'JWT'])), '+/', '-_'), '=');
            $payload = rtrim(strtr(base64_encode(json_encode(['sub' => 'u', 'iss' => 'https://example.zitadel.cloud', 'exp' => time() + 3600])), '+/', '-_'), '=');
            $token   = "{$header}.{$payload}.";

            self::assertNull($this->validator->validate($token), "alg={$alg} should be rejected");
        }
    }

    /**
     * `alg: ""` (empty string) must be rejected. An empty string is not a valid
     * algorithm name; Algorithm::tryFrom('') returns null which causes rejection
     * at step 7. This confirms that the guard at step 5 (is_string check) does not
     * accidentally accept empty strings as a valid algorithm.
     */
    public function testRejectsEmptyStringAlgorithm(): void
    {
        $header  = rtrim(strtr(base64_encode(json_encode(['alg' => '', 'typ' => 'JWT'])), '+/', '-_'), '=');
        $payload = rtrim(strtr(base64_encode(json_encode(['sub' => 'u', 'iss' => 'https://example.zitadel.cloud', 'exp' => time() + 3600])), '+/', '-_'), '=');
        $token   = "{$header}.{$payload}.";

        self::assertNull($this->validator->validate($token));
    }

    // ---------------------------------------------------------------------------
    // typ header — trailing space and other whitespace variants (attack pattern 4)
    // ---------------------------------------------------------------------------

    /**
     * `typ: "JWT "` (trailing space) must be rejected. strtolower('JWT ') === 'jwt '
     * which does not match any entry in the allowed list (['jwt', 'at+jwt']).
     * This confirms that the typ check is strict and does not silently trim values.
     */
    public function testRejectsTypHeaderWithTrailingSpace(): void
    {
        foreach (['JWT ', ' JWT', 'JWT\t', 'at+JWT '] as $typ) {
            $header  = rtrim(strtr(base64_encode(json_encode(['alg' => 'RS256', 'typ' => $typ])), '+/', '-_'), '=');
            $payload = rtrim(strtr(base64_encode(json_encode(['sub' => 'u', 'iss' => 'https://example.zitadel.cloud', 'exp' => time() + 3600])), '+/', '-_'), '=');
            $token   = "{$header}.{$payload}.fakesig";

            self::assertNull($this->validator->validate($token), "typ={$typ} should be rejected");
        }
    }

    // ---------------------------------------------------------------------------
    // kid: null in header (attack pattern 5)
    // ---------------------------------------------------------------------------

    /**
     * When the JWT header contains `"kid": null`, the validator must not pass the
     * literal null to getPublicKey as if it were a valid key ID. The null-coalescing
     * guard (`isset($header['kid']) && is_string($header['kid'])`) converts null to
     * a PHP null which is the correct "no key ID provided" sentinel.
     *
     * The resulting token is still rejected (null kid may not resolve to a key in
     * the mock), but the important thing is that the validator does not crash or
     * accept a null kid as a match.
     */
    public function testNullKidInHeaderIsHandledSafely(): void
    {
        // Build a header with explicit kid: null
        $header  = rtrim(strtr(base64_encode(json_encode(['alg' => 'RS256', 'typ' => 'JWT', 'kid' => null])), '+/', '-_'), '=');
        $payload = rtrim(strtr(base64_encode(json_encode(['sub' => 'u', 'iss' => 'https://example.zitadel.cloud', 'exp' => time() + 3600])), '+/', '-_'), '=');
        $token   = "{$header}.{$payload}.fakesig";

        // Should return null (no key found or bad sig), not throw
        self::assertNull($this->validator->validate($token));
    }

    // ---------------------------------------------------------------------------
    // alg as array (attack pattern 6)
    // ---------------------------------------------------------------------------

    /**
     * When `alg` is a JSON array rather than a string (e.g. `["RS256"]`), the
     * is_string() guard at step 5 must reject the token immediately. Without this
     * guard, passing an array to Algorithm::tryFrom() could produce a type error.
     */
    public function testRejectsAlgClaimThatIsAnArray(): void
    {
        $header  = rtrim(strtr(base64_encode(json_encode(['alg' => ['RS256'], 'typ' => 'JWT'])), '+/', '-_'), '=');
        $payload = rtrim(strtr(base64_encode(json_encode(['sub' => 'u', 'iss' => 'https://example.zitadel.cloud', 'exp' => time() + 3600])), '+/', '-_'), '=');
        $token   = "{$header}.{$payload}.fakesig";

        self::assertNull($this->validator->validate($token));
    }

    // ---------------------------------------------------------------------------
    // exp as float (attack pattern 7)
    // ---------------------------------------------------------------------------

    /**
     * `exp` encoded as a JSON float (e.g. 1234567890.0 or 9999999999.9) must be
     * rejected. PHP's json_decode() returns a float for such values, and is_int()
     * returns false for floats — including floats that happen to be whole numbers.
     * An attacker cannot use a float exp to represent a past-expiry time as a future
     * one, but we confirm rejection to ensure the type gate is solid.
     */
    public function testRejectsExpClaimThatIsAFloat(): void
    {
        // json_encode(1.0) produces "1.0" which json_decode returns as float
        // We inject a raw JSON payload to guarantee the float encoding
        $headerB64  = rtrim(strtr(base64_encode(json_encode(['alg' => 'RS256', 'typ' => 'JWT'])), '+/', '-_'), '=');
        // Manually craft payload JSON with a float exp
        $payloadJson = '{"sub":"u","iss":"https://example.zitadel.cloud","exp":' . (time() + 3600) . '.0,"iat":' . time() . '}';
        $payloadB64  = rtrim(strtr(base64_encode($payloadJson), '+/', '-_'), '=');
        $token       = "{$headerB64}.{$payloadB64}.fakesig";

        self::assertNull($this->validator->validate($token));
    }

    // ---------------------------------------------------------------------------
    // aud as nested array (attack pattern 8)
    // ---------------------------------------------------------------------------

    /**
     * When `aud` is a nested array such as `[["my-app"]]`, the inner arrays are not
     * strings and must be filtered out by the is_string() gate before the
     * array_intersect() comparison. The result is an empty actual-audience list,
     * which cannot satisfy any configured audience requirement.
     */
    public function testRejectsNestedArrayAudience(): void
    {
        [$token, $mockCache] = $this->buildRs256Token([
            'sub' => 'u',
            'iss' => 'https://example.zitadel.cloud',
            'exp' => time() + 3600,
            'iat' => time(),
            'aud' => [['my-app']],   // nested array — not a string
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

    // ---------------------------------------------------------------------------
    // iss homoglyph (attack pattern 9)
    // ---------------------------------------------------------------------------

    /**
     * A token whose `iss` claim uses a visually-similar Unicode character in place
     * of an ASCII character (e.g. Cyrillic 'е' instead of Latin 'e') must be
     * rejected. The strict `!==` comparison used at step 12 is byte-for-byte, so
     * different Unicode codepoints with the same visual appearance do not match.
     */
    public function testRejectsIssWithHomoglyphUnicode(): void
    {
        // Cyrillic small letter 'е' (U+0435) looks identical to Latin 'e' (U+0065)
        // 'https://examplе.zitadel.cloud' with a Cyrillic е in 'example'
        $homoglyphIss = "https://exampl\xd0\xb5.zitadel.cloud";  // Cyrillic е

        [$token, $mockCache] = $this->buildRs256Token([
            'sub' => 'u',
            'iss' => $homoglyphIss,
            'exp' => time() + 3600,
            'iat' => time(),
        ]);

        // config->issuerUrl is the real ASCII URL, must not match the homoglyph
        self::assertNull((new TokenValidator($this->config, $mockCache))->validate($token));
    }

    // ---------------------------------------------------------------------------
    // given_name / family_name claims — coercion when not a string
    // ---------------------------------------------------------------------------

    /**
     * When `given_name` or `family_name` in the JWT payload is not a string,
     * the validator must coerce it to null on the returned Claims object.
     */
    public function testGivenNameAndFamilyNameCoercedToNullWhenNotString(): void
    {
        [$token, $mockCache] = $this->buildRs256Token([
            'sub'         => 'u',
            'iss'         => 'https://example.zitadel.cloud',
            'exp'         => time() + 3600,
            'iat'         => time(),
            'given_name'  => 42,
            'family_name' => false,
        ]);

        $claims = (new TokenValidator($this->config, $mockCache))->validate($token);
        self::assertInstanceOf(Claims::class, $claims);
        self::assertNull($claims->givenName);
        self::assertNull($claims->familyName);
    }

    /**
     * When `given_name` and `family_name` are valid strings they must be
     * returned unchanged in the Claims object.
     */
    public function testGivenNameAndFamilyNameReturnedWhenStrings(): void
    {
        [$token, $mockCache] = $this->buildRs256Token([
            'sub'         => 'u',
            'iss'         => 'https://example.zitadel.cloud',
            'exp'         => time() + 3600,
            'iat'         => time(),
            'given_name'  => 'Jane',
            'family_name' => 'Doe',
        ]);

        $claims = (new TokenValidator($this->config, $mockCache))->validate($token);
        self::assertInstanceOf(Claims::class, $claims);
        self::assertSame('Jane', $claims->givenName);
        self::assertSame('Doe', $claims->familyName);
    }

    // ---------------------------------------------------------------------------
    // Step 11 — tampered signature (valid key, wrong signature bytes)
    // ---------------------------------------------------------------------------

    /**
     * A token whose signature has been replaced entirely must be rejected at
     * step 11 even when every other field is correct and the public key is found.
     * This test confirms the openssl_verify() !== 1 branch.
     *
     * We replace the whole signature with a base64url-encoded string of zero
     * bytes to ensure the change is unambiguous — a single-character flip at
     * the trailing position can land on padding bits and leave the decoded value
     * unchanged for certain base64url strings.
     */
    public function testRejectsTokenWithTamperedSignature(): void
    {
        [$token, $mockCache] = $this->buildRs256Token([
            'sub' => 'u',
            'iss' => 'https://example.zitadel.cloud',
            'exp' => time() + 3600,
            'iat' => time(),
        ]);

        // Replace the signature segment with 256 zero bytes (RSA-2048 sig size).
        $parts    = explode('.', $token);
        $parts[2] = rtrim(strtr(base64_encode(str_repeat("\x00", 256)), '+/', '-_'), '=');
        $tamperedToken = implode('.', $parts);

        self::assertNull((new TokenValidator($this->config, $mockCache))->validate($tamperedToken));
    }

    // ---------------------------------------------------------------------------
    // exp — missing exp claim
    // ---------------------------------------------------------------------------

    /**
     * A token without an `exp` claim must be rejected. The validator requires
     * exp to be a present integer, so a missing exp (null) fails the `is_int`
     * check at step 14.
     */
    public function testReturnsNullForMissingExp(): void
    {
        [$token, $mockCache] = $this->buildRs256Token([
            'sub' => 'u',
            'iss' => 'https://example.zitadel.cloud',
            'iat' => time(),
            // no 'exp' key
        ]);

        self::assertNull((new TokenValidator($this->config, $mockCache))->validate($token));
    }

    /**
     * `exp` encoded as a JSON string (e.g. "9999999999") must be rejected.
     * A string `exp` would pass is_string() checks but fails is_int(), preventing
     * an attacker from bypassing the expiry check by supplying a string value.
     */
    public function testRejectsExpClaimThatIsAString(): void
    {
        $headerB64   = rtrim(strtr(base64_encode(json_encode(['alg' => 'RS256', 'typ' => 'JWT'])), '+/', '-_'), '=');
        // Craft a payload with exp as a JSON string, not an integer.
        $payloadJson = '{"sub":"u","iss":"https://example.zitadel.cloud","exp":"' . (time() + 3600) . '","iat":' . time() . '}';
        $payloadB64  = rtrim(strtr(base64_encode($payloadJson), '+/', '-_'), '=');
        $token       = "{$headerB64}.{$payloadB64}.fakesig";

        self::assertNull($this->validator->validate($token));
    }

    /**
     * `sub` encoded as an integer (e.g. 12345) must be rejected.
     * RFC 7519 §4.1.2 specifies sub as a string; a non-string value fails the
     * is_string() gate at step 17 and must cause null to be returned.
     */
    public function testReturnsNullWhenSubIsInteger(): void
    {
        $headerB64   = rtrim(strtr(base64_encode(json_encode(['alg' => 'RS256', 'typ' => 'JWT'])), '+/', '-_'), '=');
        $payloadJson = '{"sub":12345,"iss":"https://example.zitadel.cloud","exp":' . (time() + 3600) . ',"iat":' . time() . '}';
        $payloadB64  = rtrim(strtr(base64_encode($payloadJson), '+/', '-_'), '=');
        $token       = "{$headerB64}.{$payloadB64}.fakesig";

        self::assertNull($this->validator->validate($token));
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
