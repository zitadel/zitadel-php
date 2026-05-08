<?php

declare(strict_types=1);

namespace Zitadel\Sdk\Test\Auth;

use PHPUnit\Framework\TestCase;
use Zitadel\Sdk\Auth\Claims;

final class ClaimsTest extends TestCase
{
    public function testConstructorMinimal(): void
    {
        $claims = new Claims(
            sub:   'user-123',
            iss:   'https://example.zitadel.cloud',
            exp:   time() + 3600,
            token: 'raw.jwt.token',
        );

        self::assertSame('user-123', $claims->sub);
        self::assertSame('https://example.zitadel.cloud', $claims->iss);
        self::assertNull($claims->name);
        self::assertNull($claims->email);
        self::assertNull($claims->givenName);
        self::assertNull($claims->familyName);
        self::assertSame([], $claims->payload);
        self::assertSame('raw.jwt.token', $claims->token);
    }

    public function testConstructorFull(): void
    {
        $exp = time() + 3600;
        $claims = new Claims(
            sub:        'user-456',
            iss:        'https://example.zitadel.cloud',
            exp:        $exp,
            token:      'raw.jwt.token',
            name:       'Jane Doe',
            email:      'jane@example.com',
            givenName:  'Jane',
            familyName: 'Doe',
            payload:    ['custom_claim' => 'value'],
        );

        self::assertSame('user-456', $claims->sub);
        self::assertSame($exp, $claims->exp);
        self::assertSame('Jane Doe', $claims->name);
        self::assertSame('jane@example.com', $claims->email);
        self::assertSame('Jane', $claims->givenName);
        self::assertSame('Doe', $claims->familyName);
        self::assertSame(['custom_claim' => 'value'], $claims->payload);
    }

    public function testIsReadonly(): void
    {
        $claims = new Claims('sub', 'iss', time(), 'tok');
        $this->expectException(\Error::class);
        // @phpstan-ignore-next-line
        $claims->sub = 'modified';
    }
}
