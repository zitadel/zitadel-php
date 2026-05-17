<?php

declare(strict_types=1);

namespace Zitadel\Sdk\Test\Bridge\CodeIgniter\Helpers;

use PHPUnit\Framework\TestCase;
use Zitadel\Sdk\Auth\Claims;
use Zitadel\Sdk\Bridge\CodeIgniter\ZitadelHolder;

/**
 * Unit tests for the `zitadel_claims()` global helper function.
 *
 * @covers \Zitadel\Sdk\Bridge\CodeIgniter\ZitadelHolder
 */
final class ZitadelHelperTest extends TestCase
{
    protected function setUp(): void
    {
        // Load the helper file (CI4 auto-loads it; in unit tests we require it directly)
        require_once __DIR__ . '/../../../../lib/Helpers/zitadel_helper.php';

        // Reset static state before each test
        ZitadelHolder::set(null);
    }

    protected function tearDown(): void
    {
        ZitadelHolder::set(null);
    }

    public function testZitadelClaimsReturnsNullWhenHolderIsEmpty(): void
    {
        self::assertNull(zitadel_claims());
    }

    public function testZitadelClaimsReturnsClaimsAfterHolderIsSet(): void
    {
        $claims = new Claims(
            sub:   'user-123',
            iss:   'https://example.zitadel.cloud',
            exp:   time() + 3600,
            token: 'raw.jwt.token',
        );

        ZitadelHolder::set($claims);

        self::assertSame($claims, zitadel_claims());
    }

    public function testZitadelClaimsReturnsNullAfterHolderIsCleared(): void
    {
        $claims = new Claims(
            sub:   'user-456',
            iss:   'https://example.zitadel.cloud',
            exp:   time() + 3600,
            token: 'raw.jwt.token',
        );

        ZitadelHolder::set($claims);
        ZitadelHolder::set(null);

        self::assertNull(zitadel_claims());
    }
}
