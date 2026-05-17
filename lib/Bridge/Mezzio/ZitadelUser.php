<?php

declare(strict_types=1);

namespace Zitadel\Sdk\Bridge\Mezzio;

use Mezzio\Authentication\UserInterface;
use Zitadel\Sdk\Auth\Claims;

/**
 * Mezzio authentication adapter wrapping a validated {@see Claims} object.
 *
 * Implements {@see UserInterface} — the contract expected by
 * `mezzio/mezzio-authentication` and `mezzio/mezzio-authorization`. The
 * {@see \Zitadel\Sdk\Middleware\ZitadelMiddleware} stores an instance of this
 * class at the `UserInterface::class` request attribute key (in addition to
 * the `zitadel.claims` attribute) when `mezzio/mezzio-authentication` is
 * installed, allowing standard Mezzio authorization middleware to consume it
 * without any custom adapter code.
 *
 * Roles are read from the `roles` key inside {@see Claims::$payload}. If
 * your Zitadel project scopes do not include a `roles` claim, override the
 * payload before wrapping, or extend this class.
 */
readonly class ZitadelUser implements UserInterface
{
    /** @param Claims $claims The validated JWT claims for this user. */
    public function __construct(public Claims $claims)
    {
    }

    /**
     * Returns the unique user identity — the JWT `sub` claim.
     *
     * @return string The Zitadel user ID from the validated token.
     */
    #[\Override]
    public function getIdentity(): string
    {
        return $this->claims->sub;
    }

    /**
     * Returns the user's roles extracted from the JWT `roles` payload key.
     *
     * Zitadel encodes project roles as a nested array under a project-specific
     * key (e.g. `urn:zitadel:iam:org:project:roles`). If your token includes
     * such a structure, flatten it before or after wrapping. Returns an empty
     * array when no `roles` key is present.
     *
     * @psalm-return iterable<int|string, string>
     * @return string[] Roles from the token payload, or an empty array.
     */
    #[\Override]
    public function getRoles(): iterable
    {
        $roles = $this->claims->payload['roles'] ?? [];

        return is_array($roles) ? array_values($roles) : [];
    }

    /**
     * Returns a single claim from the JWT payload by name.
     *
     * Promotes typed {@see Claims} properties first (`sub`, `iss`, `exp`,
     * `name`, `email`, `given_name`, `family_name`), then falls through to the
     * raw {@see Claims::$payload} array.
     *
     * @param string     $name    Claim name (e.g. `'email'`, `'name'`).
     * @param mixed|null $default Returned when the claim is absent.
     * @return mixed The claim value, or `$default` if not found.
     */
    #[\Override]
    public function getDetail(string $name, $default = null): mixed
    {
        return match ($name) {
            'sub'         => $this->claims->sub,
            'iss'         => $this->claims->iss,
            'exp'         => $this->claims->exp,
            'name'        => $this->claims->name,
            'email'       => $this->claims->email,
            'given_name'  => $this->claims->givenName,
            'family_name' => $this->claims->familyName,
            default       => $this->claims->payload[$name] ?? $default,
        };
    }

    /**
     * Returns all JWT payload claims as an associative array.
     *
     * The raw {@see Claims::$payload} already contains all decoded claims
     * (including `sub`, `iss`, `exp`, `iat`, `aud`, `nbf`, and any custom
     * Zitadel metadata). Promoted typed properties are included via the
     * payload rather than re-merged, keeping this O(1).
     *
     * @psalm-return array<string, mixed>
     * @return array<string, mixed> Full decoded JWT payload.
     */
    #[\Override]
    public function getDetails(): array
    {
        return $this->claims->payload;
    }
}
