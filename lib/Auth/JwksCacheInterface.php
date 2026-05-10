<?php

declare(strict_types=1);

namespace Zitadel\Sdk\Auth;

/**
 * Contract for the JWKS public-key cache.
 *
 * Implemented by {@see JwksCache}. Extracted as an interface to allow test
 * doubles without requiring the concrete class to be non-final.
 */
interface JwksCacheInterface
{
    /**
     * Returns the public key for a given JWKS URI and key ID.
     *
     * @param string      $jwksUri        JWKS endpoint URL from the issuer.
     * @param string|null $kid            Key ID from the JWT header; null when absent.
     * @param string      $alg            Algorithm from the JWT header.
     * @param int         $ttlSeconds     Cache TTL in seconds.
     * @param int         $timeoutSeconds cURL timeout in seconds.
     * @return \OpenSSLAsymmetricKey|null Null when no matching key is found.
     */
    public function getPublicKey(
        string $jwksUri,
        ?string $kid,
        string $alg,
        int $ttlSeconds,
        int $timeoutSeconds,
    ): ?\OpenSSLAsymmetricKey;

    /**
     * Evicts all entries from the in-process key store.
     *
     * Intended for long-running runtimes (Swoole, RoadRunner, FrankenPHP) where
     * the static cache persists across requests. Call this from a key-rotation
     * webhook handler to force an immediate JWKS re-fetch on the next validation.
     */
    public function clearCache(): void;
}
