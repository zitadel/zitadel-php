<?php

declare(strict_types=1);

namespace Zitadel\Sdk\Bridge\Laravel\Auth;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Http\Request;

/**
 * Laravel Auth guard backed by the `zitadel.claims` request attribute.
 *
 * Register in your `config/auth.php`:
 * ```php
 * 'guards' => [
 *     'zitadel' => ['driver' => 'zitadel'],
 * ],
 * ```
 *
 * Then use `auth('zitadel')->user()` or — if set as default — `auth()->user()`.
 * Registered automatically by {@see \Zitadel\Sdk\Bridge\Laravel\ZitadelServiceProvider}.
 *
 * Not final — standard Laravel guards (SessionGuard, TokenGuard) are not final;
 * allowing extension lets tests use `Auth::fake()` and `actingAs()` without
 * special workarounds.
 */
class ZitadelGuard implements Guard
{
    // Mutable by design: required by Guard::setUser() and called by actingAs() in test contexts.
    private ?ZitadelUser $user = null;

    /** @param Request $request The current Illuminate HTTP request. */
    public function __construct(private readonly Request $request) {}

    #[\Override]
    public function check(): bool
    {
        return $this->user() !== null;
    }

    #[\Override]
    public function guest(): bool
    {
        return $this->user() === null;
    }

    #[\Override]
    public function user(): ?ZitadelUser
    {
        return $this->user ??= $this->resolve();
    }

    #[\Override]
    public function id(): ?string
    {
        return $this->user()?->claims->sub;
    }

    #[\Override]
    public function validate(array $credentials = []): bool
    {
        return false;
    }

    #[\Override]
    public function hasUser(): bool
    {
        return $this->user !== null;
    }

    #[\Override]
    public function setUser(Authenticatable $user): static
    {
        $this->user = $user instanceof ZitadelUser ? $user : null;

        return $this;
    }

    private function resolve(): ?ZitadelUser
    {
        $claims = $this->request->attributes->get('zitadel.claims');

        return $claims !== null ? new ZitadelUser($claims) : null;
    }
}
