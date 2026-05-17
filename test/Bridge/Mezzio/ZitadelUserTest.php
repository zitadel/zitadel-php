<?php

declare(strict_types=1);

namespace Zitadel\Sdk\Test\Bridge\Mezzio;

use PHPUnit\Framework\TestCase;
use Zitadel\Sdk\Auth\Claims;
use Zitadel\Sdk\Bridge\Mezzio\ZitadelUser;

/**
 * Unit tests for {@see ZitadelUser} — the Mezzio {@see \Mezzio\Authentication\UserInterface} adapter.
 *
 * @covers \Zitadel\Sdk\Bridge\Mezzio\ZitadelUser
 */
final class ZitadelUserTest extends TestCase
{
    private Claims $claims;

    protected function setUp(): void
    {
        $this->claims = new Claims(
            sub:        'user-789',
            iss:        'https://example.zitadel.cloud',
            exp:        time() + 3600,
            token:      'raw.jwt.token',
            name:       'Alice Example',
            email:      'alice@example.com',
            givenName:  'Alice',
            familyName: 'Example',
            payload:    [
                'sub'         => 'user-789',
                'iss'         => 'https://example.zitadel.cloud',
                'exp'         => time() + 3600,
                'email'       => 'alice@example.com',
                'name'        => 'Alice Example',
                'given_name'  => 'Alice',
                'family_name' => 'Example',
                'roles'       => ['admin', 'editor'],
                'custom_key'  => 'custom_value',
            ],
        );
    }

    public function testGetIdentityReturnsSub(): void
    {
        $user = new ZitadelUser($this->claims);

        self::assertSame('user-789', $user->getIdentity());
    }

    public function testGetRolesReturnsRolesFromPayload(): void
    {
        $user = new ZitadelUser($this->claims);

        self::assertSame(['admin', 'editor'], iterator_to_array($user->getRoles()));
    }

    public function testGetRolesReturnsEmptyArrayWhenNoRolesInPayload(): void
    {
        $claims = new Claims(
            sub:   'user-no-roles',
            iss:   'https://example.zitadel.cloud',
            exp:   time() + 3600,
            token: 'raw.jwt.token',
        );
        $user = new ZitadelUser($claims);

        self::assertSame([], iterator_to_array($user->getRoles()));
    }

    public function testGetDetailReturnsEmailFromTypedProperty(): void
    {
        $user = new ZitadelUser($this->claims);

        self::assertSame('alice@example.com', $user->getDetail('email'));
    }

    public function testGetDetailReturnsNameFromTypedProperty(): void
    {
        $user = new ZitadelUser($this->claims);

        self::assertSame('Alice Example', $user->getDetail('name'));
    }

    public function testGetDetailReturnsGivenNameFromTypedProperty(): void
    {
        $user = new ZitadelUser($this->claims);

        self::assertSame('Alice', $user->getDetail('given_name'));
    }

    public function testGetDetailReturnsFamilyNameFromTypedProperty(): void
    {
        $user = new ZitadelUser($this->claims);

        self::assertSame('Example', $user->getDetail('family_name'));
    }

    public function testGetDetailReturnsCustomKeyFromPayload(): void
    {
        $user = new ZitadelUser($this->claims);

        self::assertSame('custom_value', $user->getDetail('custom_key'));
    }

    public function testGetDetailReturnsDefaultWhenKeyAbsent(): void
    {
        $user = new ZitadelUser($this->claims);

        self::assertNull($user->getDetail('nonexistent'));
        self::assertSame('fallback', $user->getDetail('nonexistent', 'fallback'));
    }

    public function testGetDetailsReturnsFullPayload(): void
    {
        $user = new ZitadelUser($this->claims);

        self::assertArrayHasKey('sub', $user->getDetails());
        self::assertArrayHasKey('email', $user->getDetails());
        self::assertArrayHasKey('custom_key', $user->getDetails());
        self::assertSame('user-789', $user->getDetails()['sub']);
    }

    public function testImplementsMezzioUserInterface(): void
    {
        $user = new ZitadelUser($this->claims);

        self::assertInstanceOf(\Mezzio\Authentication\UserInterface::class, $user);
    }

    public function testClaimsPropertyIsPubliclyAccessible(): void
    {
        $user = new ZitadelUser($this->claims);

        self::assertSame($this->claims, $user->claims);
    }
}
