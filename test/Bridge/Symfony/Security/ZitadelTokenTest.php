<?php

declare(strict_types=1);

namespace Zitadel\Sdk\Test\Bridge\Symfony\Security;

use PHPUnit\Framework\TestCase;
use Symfony\Component\Security\Core\Authentication\Token\AbstractToken;
use Zitadel\Sdk\Auth\Claims;
use Zitadel\Sdk\Bridge\Symfony\Security\ZitadelToken;
use Zitadel\Sdk\Bridge\Symfony\Security\ZitadelUser;

/**
 * Unit tests for {@see ZitadelToken} and {@see ZitadelUser}.
 *
 * @covers \Zitadel\Sdk\Bridge\Symfony\Security\ZitadelToken
 * @covers \Zitadel\Sdk\Bridge\Symfony\Security\ZitadelUser
 */
final class ZitadelTokenTest extends TestCase
{
    private Claims $claims;

    protected function setUp(): void
    {
        $this->claims = new Claims(
            sub:        'user-sym-001',
            iss:        'https://example.zitadel.cloud',
            exp:        time() + 3600,
            token:      'signed.jwt.string',
            name:       'Bob Symfony',
            email:      'bob@symfony.test',
            payload:    [
                'sub'   => 'user-sym-001',
                'email' => 'bob@symfony.test',
                'roles' => ['ROLE_ADMIN', 'ROLE_USER'],
            ],
        );
    }

    // ── ZitadelUser ────────────────────────────────────────────────────────

    public function testGetUserIdentifierReturnsSub(): void
    {
        $user = new ZitadelUser($this->claims);

        self::assertSame('user-sym-001', $user->getUserIdentifier());
    }

    public function testGetRolesIncludesRolesFromPayload(): void
    {
        $user = new ZitadelUser($this->claims);

        self::assertContains('ROLE_ADMIN', $user->getRoles());
        self::assertContains('ROLE_USER', $user->getRoles());
    }

    public function testGetRolesAlwaysIncludesRoleUser(): void
    {
        $claims = new Claims(
            sub:   'user-no-roles',
            iss:   'https://example.zitadel.cloud',
            exp:   time() + 3600,
            token: 'signed.jwt.string',
        );
        $user = new ZitadelUser($claims);

        self::assertContains('ROLE_USER', $user->getRoles());
    }

    public function testEraseCredentialsDoesNothing(): void
    {
        $user = new ZitadelUser($this->claims);

        // Should not throw
        $user->eraseCredentials();
        self::assertSame('user-sym-001', $user->getUserIdentifier());
    }

    public function testImplementsSymfonyUserInterface(): void
    {
        $user = new ZitadelUser($this->claims);

        self::assertInstanceOf(\Symfony\Component\Security\Core\User\UserInterface::class, $user);
    }

    // ── ZitadelToken ───────────────────────────────────────────────────────

    public function testTokenWrapsUser(): void
    {
        $user  = new ZitadelUser($this->claims);
        $token = new ZitadelToken($user);

        self::assertSame($user, $token->getUser());
    }

    public function testTokenUserIdentifierMatchesSub(): void
    {
        $token = new ZitadelToken(new ZitadelUser($this->claims));

        self::assertSame('user-sym-001', $token->getUserIdentifier());
    }

    public function testTokenDefaultFirewallNameIsMain(): void
    {
        $token = new ZitadelToken(new ZitadelUser($this->claims));

        self::assertSame('main', $token->getFirewallName());
    }

    public function testTokenCustomFirewallName(): void
    {
        $token = new ZitadelToken(new ZitadelUser($this->claims), 'api');

        self::assertSame('api', $token->getFirewallName());
    }

    public function testGetJwtReturnsRawToken(): void
    {
        $token = new ZitadelToken(new ZitadelUser($this->claims));

        self::assertSame('signed.jwt.string', $token->getJwt());
    }

    public function testGetClaimsReturnsClaims(): void
    {
        $token = new ZitadelToken(new ZitadelUser($this->claims));

        self::assertSame($this->claims, $token->getClaims());
    }

    public function testTokenExtendsAbstractToken(): void
    {
        $token = new ZitadelToken(new ZitadelUser($this->claims));

        self::assertInstanceOf(AbstractToken::class, $token);
    }

    public function testRolesArePassedToAbstractToken(): void
    {
        $token = new ZitadelToken(new ZitadelUser($this->claims));

        self::assertContains('ROLE_ADMIN', $token->getRoleNames());
        self::assertContains('ROLE_USER', $token->getRoleNames());
    }
}
