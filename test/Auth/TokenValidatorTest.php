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
