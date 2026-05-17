<?php

declare(strict_types=1);

namespace Zitadel\Sdk\Bridge\Symfony\Security;

use Symfony\Component\Security\Core\User\UserInterface;
use Zitadel\Sdk\Auth\Claims;

/**
 * Symfony Security user adapter wrapping a validated {@see Claims} object.
 *
 * Stored inside {@see ZitadelToken} and returned by `$this->getUser()` in
 * controllers that extend `AbstractController`. Roles are read from the JWT
 * `roles` payload key; when absent, only `ROLE_USER` is granted.
 *
 * Not final — applications may extend this class to add project-specific role
 * mapping (e.g. mapping Zitadel organisation roles to Symfony ROLE_ strings).
 */
class ZitadelUser implements UserInterface
{
    /** @param Claims $claims The validated JWT claims for this user. */
    public function __construct(public readonly Claims $claims)
    {
    }

    /**
     * Returns the user's identifier — the JWT `sub` claim (Zitadel user ID).
     *
     * Used by Symfony Security to identify this user in the token storage and
     * in log output. Matches `getAuthIdentifier()` on the Laravel counterpart.
     *
     * @return non-empty-string The Zitadel user ID.
     */
    #[\Override]
    public function getUserIdentifier(): string
    {
        return $this->claims->sub;
    }

    /**
     * Returns the Symfony roles granted to this user.
     *
     * Reads from `$claims->payload['roles']` when present; always includes
     * `ROLE_USER` so that Symfony's `isGranted('ROLE_USER')` returns true for
     * any authenticated Zitadel user.
     *
     * @return string[] Non-empty array of Symfony-format role strings.
     */
    #[\Override]
    public function getRoles(): array
    {
        $roles = $this->claims->payload['roles'] ?? [];
        $roles = is_array($roles) ? array_values($roles) : [];

        if (!in_array('ROLE_USER', $roles, true)) {
            $roles[] = 'ROLE_USER';
        }

        return $roles;
    }

    /**
     * No-op — Zitadel users carry no local credentials to erase.
     *
     * @deprecated since Symfony 7.3; erase credentials using __serialize() instead.
     */
    #[\Override]
    public function eraseCredentials(): void
    {
        // JWT-based auth has no locally-stored credentials to erase.
    }
}
