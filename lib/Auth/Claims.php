<?php

declare(strict_types=1);

namespace Zitadel\Sdk\Auth;

/**
 * Decoded and validated JWT claims.
 *
 * An instance is attached to the request after successful token validation and
 * is accessible to controllers via the framework bridge (see framework guides).
 * All properties are readonly — the object is immutable once constructed.
 *
 * Standard OIDC fields are promoted as typed properties; any additional claims
 * present in the token payload (custom Zitadel metadata, roles, etc.) are
 * available in {@see $payload}. Standard JWT claims that are validated by
 * {@see \Zitadel\Sdk\Auth\TokenValidator} but not promoted as typed properties —
 * `iat`, `nbf`, and `aud` — are also accessible via `$payload`. The raw signed
 * JWT string is exposed via {@see $token} for forwarding to downstream services.
 */
readonly class Claims
{
    /**
     * @param string               $sub        Subject identifier — the Zitadel user ID.
     * @param string               $iss        Issuer URL — must match
     *                                         {@see \Zitadel\Sdk\Config\ZitadelConfig::$issuerUrl}.
     * @param int                  $exp        Expiration timestamp (Unix epoch seconds).
     * @param string               $token      Raw signed JWT string. Forward this as
     *                                         `Authorization: Bearer` to downstream services
     *                                         that independently validate the token.
     *                                         Equivalent to the TypeScript `x-nextgen-auth-token`
     *                                         header tunnel.
     * @param string|null          $name       Full display name from the OIDC `name` claim.
     * @param string|null          $email      Email address from the OIDC `email` claim.
     * @param string|null          $givenName  Given (first) name from the OIDC `given_name` claim.
     * @param string|null          $familyName Family (last) name from the OIDC `family_name` claim.
     * @param array<string, mixed> $payload    Full decoded JWT payload as an associative array.
     *                                         Use this to access any claim not exposed as a typed
     *                                         property (e.g. custom Zitadel roles, metadata).
     */
    public function __construct(
        public string  $sub,
        public string  $iss,
        public int     $exp,
        public string  $token,
        public ?string $name        = null,
        public ?string $email       = null,
        public ?string $givenName   = null,
        public ?string $familyName  = null,
        public array   $payload     = [],
    ) {
    }
}
