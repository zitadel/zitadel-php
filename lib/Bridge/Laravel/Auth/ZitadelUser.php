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

    #[\Override]
    public function getAuthIdentifierName(): string
    {
        return 'sub';
    }

    #[\Override]
    public function getAuthIdentifier(): string
    {
        return $this->claims->sub;
    }

    #[\Override]
    public function getAuthPasswordName(): ?string
    {
        return null;
    }

    #[\Override]
    public function getAuthPassword(): ?string
    {
        return null;
    }

    #[\Override]
    public function getRememberToken(): string
    {
        return '';
    }

    #[\Override]
    public function setRememberToken($value): void
    {
        // JWT auth has no remember-token concept — throw rather than silently discarding the value
        throw new \LogicException(
            'Remember tokens are not supported by ZitadelUser (JWT-based auth has no persistent session tokens).'
        );
    }

    #[\Override]
    public function getRememberTokenName(): string
    {
        return '';
    }
}
