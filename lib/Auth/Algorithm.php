<?php

declare(strict_types=1);

namespace Zitadel\Sdk\Auth;

/**
 * Supported JWT signing algorithms.
 *
 * Each case carries two pieces of metadata used by {@see TokenValidator}:
 * the OpenSSL algorithm constant for {@see openssl_verify()} and a flag
 * indicating whether the algorithm uses an elliptic-curve key (which requires
 * converting the raw IEEE P1363 signature to DER before verification).
 */
enum Algorithm: string
{
    case RS256 = 'RS256';
    case RS384 = 'RS384';
    case RS512 = 'RS512';
    case ES256 = 'ES256';
    case ES384 = 'ES384';
    case ES512 = 'ES512';

    /**
     * Returns the OpenSSL digest algorithm constant for this signing algorithm.
     *
     * Used as the fourth argument to {@see openssl_verify()}.
     */
    public function opensslAlgo(): int
    {
        return match ($this) {
            self::RS256, self::ES256 => OPENSSL_ALGO_SHA256,
            self::RS384, self::ES384 => OPENSSL_ALGO_SHA384,
            self::RS512, self::ES512 => OPENSSL_ALGO_SHA512,
        };
    }

    /**
     * Returns true when this algorithm uses an elliptic-curve key.
     *
     * EC signatures from Zitadel are encoded as raw IEEE P1363 (r||s), but
     * {@see openssl_verify()} expects DER-encoded ASN.1. {@see TokenValidator}
     * uses this flag to decide whether to convert the signature before passing
     * it to OpenSSL.
     */
    public function isEc(): bool
    {
        return match ($this) {
            self::ES256, self::ES384, self::ES512 => true,
            default => false,
        };
    }

    /**
     * Returns the expected JWK `kty` value for this algorithm.
     *
     * Used by {@see JwksCache::selectKey()} to reject keys whose type does not
     * match the algorithm declared in the token header. For example, an RSA key
     * must not be returned for an ES256 token even when the `kid` matches.
     */
    public function expectedKty(): string
    {
        return match ($this) {
            self::ES256, self::ES384, self::ES512 => 'EC',
            default => 'RSA',
        };
    }

    /**
     * Returns the expected JWK `crv` value for EC algorithms, or null for RSA.
     *
     * ES256 requires curve P-256, ES384 requires P-384, ES512 requires P-521.
     * Used by {@see JwksCache::selectKey()} to reject EC keys on the wrong curve.
     */
    public function expectedCrv(): ?string
    {
        return match ($this) {
            self::ES256 => 'P-256',
            self::ES384 => 'P-384',
            self::ES512 => 'P-521',
            default     => null,
        };
    }
}
