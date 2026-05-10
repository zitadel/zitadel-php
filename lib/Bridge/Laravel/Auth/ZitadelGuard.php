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
    public function __construct(private readonly Request $request)
    {
    }

    /**
     * Determines whether the current request carries a validated session.
     *
     * @return bool True if a {@see ZitadelUser} was resolved from the request attributes.
     */
    #[\Override]
    public function check(): bool
    {
        return $this->user() !== null;
    }

    /**
     * Determines whether the current request is unauthenticated.
     *
     * @return bool True when no validated session exists.
     */
    #[\Override]
    public function guest(): bool
    {
        return $this->user() === null;
    }

    /**
     * Returns the authenticated user for this request, or null if unauthenticated.
     *
     * Lazily resolves the user from the `zitadel.claims` request attribute on first call
     * and caches the result for the lifetime of this guard instance.
     *
     * @return ZitadelUser|null The authenticated user, or null when no valid claims are present.
     */
    #[\Override]
    public function user(): ?ZitadelUser
    {
        return $this->user ??= $this->resolve();
    }

    /**
     * Returns the subject (`sub`) claim from the authenticated user's JWT, or null.
     *
     * @return string|null The user identifier string, or null if unauthenticated.
     */
    #[\Override]
    public function id(): ?string
    {
        return $this->user()?->claims->sub;
    }

    /**
     * Credential-based validation is not supported — Zitadel uses PKCE/JWT, not passwords.
     *
     * @param array<string, mixed> $credentials Ignored.
     * @return bool Always false.
     */
    #[\Override]
    public function validate(array $credentials = []): bool
    {
        return false;
    }

    /**
     * Returns whether a user has been set on the guard instance (including via {@see setUser}).
     *
     * @return bool True if `$this->user` is non-null without triggering lazy resolution.
     */
    #[\Override]
    public function hasUser(): bool
    {
        return $this->user !== null;
    }

    /**
     * Sets the currently authenticated user on the guard.
     *
     * Accepts only {@see ZitadelUser} instances; any other `Authenticatable` sets the user
     * to null. This allows `actingAs()` in tests to inject a typed user directly.
     *
     * @param Authenticatable $user The user to set; silently ignored if not a {@see ZitadelUser}.
     * @return static The guard instance for fluent chaining.
     */
    #[\Override]
    public function setUser(Authenticatable $user): static
    {
        $this->user = $user instanceof ZitadelUser ? $user : null;

        return $this;
    }

    /**
     * Resolves the authenticated user from the `zitadel.claims` request attribute.
     *
     * @return ZitadelUser|null A new user wrapping the validated claims, or null if none exist.
     */
    private function resolve(): ?ZitadelUser
    {
        $claims = $this->request->attributes->get('zitadel.claims');

        return $claims !== null ? new ZitadelUser($claims) : null;
    }
}
