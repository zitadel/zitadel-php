<?php

declare(strict_types=1);

namespace Zitadel\Sdk\Test\Auth;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Zitadel\Sdk\Auth\Algorithm;

final class AlgorithmTest extends TestCase
{
    #[DataProvider('opensslAlgoProvider')]
    public function testOpensslAlgo(Algorithm $algorithm, int $expected): void
    {
        self::assertSame($expected, $algorithm->opensslAlgo());
    }

    public static function opensslAlgoProvider(): array
    {
        return [
            [Algorithm::RS256, OPENSSL_ALGO_SHA256],
            [Algorithm::RS384, OPENSSL_ALGO_SHA384],
            [Algorithm::RS512, OPENSSL_ALGO_SHA512],
            [Algorithm::ES256, OPENSSL_ALGO_SHA256],
            [Algorithm::ES384, OPENSSL_ALGO_SHA384],
            [Algorithm::ES512, OPENSSL_ALGO_SHA512],
        ];
    }

    #[DataProvider('isEcProvider')]
    public function testIsEc(Algorithm $algorithm, bool $expected): void
    {
        self::assertSame($expected, $algorithm->isEc());
    }

    public static function isEcProvider(): array
    {
        return [
            [Algorithm::RS256, false],
            [Algorithm::RS384, false],
            [Algorithm::RS512, false],
            [Algorithm::ES256, true],
            [Algorithm::ES384, true],
            [Algorithm::ES512, true],
        ];
    }

    public function testFromValue(): void
    {
        self::assertSame(Algorithm::RS256, Algorithm::from('RS256'));
        self::assertSame(Algorithm::ES256, Algorithm::from('ES256'));
        self::assertNull(Algorithm::tryFrom('INVALID'));
    }
}
