<?php

declare(strict_types=1);

namespace Zitadel\Sdk\Auth;

/**
 * Process-scoped cache for JWKS public keys.
 *
 * Keys are fetched from the JWKS endpoint on first use and cached in a static
 * array for `$ttlSeconds` seconds. This mirrors the module-level `Map` used in
 * the TypeScript reference implementation (`jwt.ts:261`).
 *
 * This is the **only** class in the library with mutable state. Mutation is
 * intentional and confined to `private static array $store` — no instance state
 * is ever modified.
 *
 * **Long-running runtimes** (Swoole, RoadRunner, FrankenPHP): the static cache
 * persists across requests within a worker process. This is intentional for
 * performance. Set `$jwksTtlSeconds` conservatively if key rotation is frequent.
 * The cache is safe to share across requests — keys are read-only once fetched.
 */
final class JwksCache
{
    /**
     * In-process key store.
     *
     * Keys: `"{jwksUri}:{kid}"` or `"{jwksUri}:__default__"` when no `kid` is present.
     * Values: `['key' => OpenSSLAsymmetricKey, 'fetchedAt' => int]`
     *
     * @var array<string, array{key: \OpenSSLAsymmetricKey, fetchedAt: int}>
     */
    private static array $store = [];

    /**
     * Returns the public key for a given JWKS URI and key ID.
     *
     * On a cache hit (key present and not yet expired), returns the cached key
     * without making any HTTP request. On a miss, fetches the JWKS endpoint via
     * cURL, parses the response, converts the matching JWK to an OpenSSL key
     * using {@see JwkConverter::toKey()}, stores it, and returns it.
     *
     * @param string      $jwksUri        JWKS endpoint URL from the issuer.
     * @param string|null $kid            Key ID from the JWT header; null when absent.
     * @param string      $alg            Algorithm from the JWT header — used to filter
     *                                    the JWK set when no `kid` is present.
     * @param int         $ttlSeconds     Cache TTL in seconds.
     * @param int         $timeoutSeconds cURL timeout in seconds.
     * @return \OpenSSLAsymmetricKey|null Null when no matching key found or unreachable.
     */
    public function getPublicKey(
        string $jwksUri,
        ?string $kid,
        string $alg,
        int $ttlSeconds,
        int $timeoutSeconds,
    ): ?\OpenSSLAsymmetricKey {
        $cacheKey = $jwksUri . ':' . ($kid ?? '__default__');
        $now      = time();

        if (
            isset(self::$store[$cacheKey]) &&
            ($now - self::$store[$cacheKey]['fetchedAt']) < $ttlSeconds
        ) {
            return self::$store[$cacheKey]['key'];
        }

        $jwks = $this->fetchJwks($jwksUri, $timeoutSeconds);
        if ($jwks === null) {
            return null;
        }

        $key = $this->selectKey($jwks, $kid, $alg);
        if ($key === null) {
            return null;
        }

        self::$store[$cacheKey] = ['key' => $key, 'fetchedAt' => $now];

        return $key;
    }

    /** @return array<string, mixed>|null */
    private function fetchJwks(string $jwksUri, int $timeoutSeconds): ?array
    {
        $ch = curl_init($jwksUri);
        if ($ch === false) {
            return null;
        }

        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => $timeoutSeconds,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
        ]);

        $body  = curl_exec($ch);
        $errno = curl_errno($ch);
        curl_close($ch);

        if ($errno !== 0 || $body === false || !is_string($body)) {
            return null;
        }

        if (!json_validate($body)) {
            return null;
        }

        /** @var array<string, mixed>|null $data */
        $data = json_decode($body, true);

        return is_array($data) ? $data : null;
    }

    /**
     * @param array<string, mixed> $jwks
     */
    private function selectKey(array $jwks, ?string $kid, string $alg): ?\OpenSSLAsymmetricKey
    {
        /** @var array<int, array<string, string>> $keys */
        $keys = $jwks['keys'] ?? [];

        $candidates = array_filter($keys, static function (array $k) use ($kid, $alg): bool {
            $useOk = !isset($k['use']) || $k['use'] === 'sig';
            $kidOk = $kid === null || ($k['kid'] ?? null) === $kid;
            $algOk = $kid !== null || !isset($k['alg']) || $k['alg'] === $alg;

            return $useOk && $kidOk && $algOk;
        });

        foreach ($candidates as $jwk) {
            try {
                return JwkConverter::toKey($jwk);
            } catch (\InvalidArgumentException) {
                continue;
            }
        }

        return null;
    }
}
