<?php

declare(strict_types=1);

namespace Zitadel\Sdk\Bridge\Symfony\Security;

use Symfony\Component\Security\Core\Authentication\Token\AbstractToken;
use Zitadel\Sdk\Auth\Claims;

/**
 * Symfony Security token wrapping a validated Zitadel {@see Claims} object.
 *
 * Created by {@see \Zitadel\Sdk\Bridge\Symfony\EventListener\ZitadelListener}
 * after successful JWT validation and stored in Symfony's
 * {@see \Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface}.
 *
 * Storing this token in token storage is what makes `$this->getUser()` work in
 * `AbstractController` — Symfony reads the user from the token, not from the
 * request attributes. All comparable Symfony auth libraries (LexikJWT,
 * HWIOAuth) follow the same pattern.
 *
 * Modelled after {@see \Symfony\Component\Security\Core\Authentication\Token\PreAuthenticatedToken}:
 * extends `AbstractToken`, sets the user on construction, stores the firewall name.
 */
final class ZitadelToken extends AbstractToken
{
    /**
     * @param ZitadelUser $user         The authenticated Symfony Security user.
     * @param string      $firewallName The name of the Symfony Security firewall
     *                                  (e.g. `'main'`). Matches the firewall key in
     *                                  `config/packages/security.yaml`.
     */
    public function __construct(
        ZitadelUser    $user,
        private string $firewallName = 'main',
    ) {
        parent::__construct($user->getRoles());
        $this->setUser($user);
    }

    /**
     * Returns the Symfony firewall name this token belongs to.
     *
     * @return string The firewall name (e.g. `'main'`).
     */
    public function getFirewallName(): string
    {
        return $this->firewallName;
    }

    /**
     * Returns the raw JWT string for forwarding to downstream services.
     *
     * Convenience accessor for the signed token stored inside the claims object.
     *
     * @return string The raw signed JWT.
     */
    public function getJwt(): string
    {
        /** @var ZitadelUser $user */
        $user = $this->getUser();

        return $user->claims->token;
    }

    /**
     * Returns the validated {@see Claims} object from the wrapped {@see ZitadelUser}.
     *
     * @return Claims The validated JWT claims.
     */
    public function getClaims(): Claims
    {
        /** @var ZitadelUser $user */
        $user = $this->getUser();

        return $user->claims;
    }

    /**
     * @return array{string, array<mixed>}
     */
    public function __serialize(): array
    {
        return [$this->firewallName, parent::__serialize()];
    }

    /**
     * @param array{string, array<mixed>} $data
     */
    public function __unserialize(array $data): void
    {
        [$this->firewallName, $parentData] = $data;
        parent::__unserialize($parentData);
    }
}
