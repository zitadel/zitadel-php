<?php

declare(strict_types=1);

namespace Zitadel\Sdk\Bridge\Laravel\Auth;

use Illuminate\Contracts\Auth\Authenticatable;
use Zitadel\Sdk\Auth\Claims;

/**
 * Laravel Authenticatable adapter wrapping a validated {@see Claims} object.
 *
 * Registered as the "user" type returned by the `zitadel` auth guard.
 * Controllers access it via `auth()->user()`, `auth('zitadel')->user()`,
 * or `$request->user()`.
 */
readonly class ZitadelUser implements Authenticatable
{
    /** @param Claims $claims The validated JWT claims for this user. */
    public function __construct(public Claims $claims)
    {
    }

    /**
     * Returns the name of the unique identifier column for this user type.
     *
     * @return string Always `'sub'` — the JWT subject claim used as the user's unique key.
     */
    #[\Override]
    public function getAuthIdentifierName(): string
    {
        return 'sub';
    }

    /**
     * Returns the unique identifier value for the authenticated user.
     *
     * @return string The `sub` claim from the validated JWT.
     */
    #[\Override]
    public function getAuthIdentifier(): string
    {
        return $this->claims->sub;
    }

    /**
     * Returns the name of the password column — not applicable to JWT auth.
     *
     * @return string|null Always null; Zitadel users have no local password.
     */
    #[\Override]
    public function getAuthPasswordName(): ?string
    {
        return null;
    }

    /**
     * Returns the hashed password — not applicable to JWT auth.
     *
     * @return string|null Always null; Zitadel users have no local password.
     */
    #[\Override]
    public function getAuthPassword(): ?string
    {
        return null;
    }

    /**
     * Returns the remember-token value — not applicable to JWT auth.
     *
     * @return string Always an empty string; JWTs are stateless and need no remember token.
     */
    #[\Override]
    public function getRememberToken(): string
    {
        return '';
    }

    /**
     * Setting a remember token is not supported — JWT auth is stateless.
     *
     * @param mixed $value Ignored.
     * @throws \LogicException Always; remember tokens are incompatible with JWT-based auth.
     */
    #[\Override]
    public function setRememberToken($value): void
    {
        // JWT auth has no remember-token concept — throw rather than silently discarding the value
        throw new \LogicException(
            'Remember tokens are not supported by ZitadelUser (JWT-based auth has no persistent session tokens).'
        );
    }

    /**
     * Returns the name of the remember-token column — not applicable to JWT auth.
     *
     * @return string Always an empty string; JWTs are stateless.
     */
    #[\Override]
    public function getRememberTokenName(): string
    {
        return '';
    }
}
