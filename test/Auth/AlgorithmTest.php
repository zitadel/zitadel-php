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

    /** @return array<int, array{Algorithm, int}> */
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

    /** @return array<int, array{Algorithm, bool}> */
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

    #[DataProvider('expectedKtyProvider')]
    public function testExpectedKty(Algorithm $algorithm, string $expected): void
    {
        self::assertSame($expected, $algorithm->expectedKty());
    }

    /** @return array<int, array{Algorithm, string}> */
    public static function expectedKtyProvider(): array
    {
        return [
            [Algorithm::RS256, 'RSA'],
            [Algorithm::RS384, 'RSA'],
            [Algorithm::RS512, 'RSA'],
            [Algorithm::ES256, 'EC'],
            [Algorithm::ES384, 'EC'],
            [Algorithm::ES512, 'EC'],
        ];
    }

    #[DataProvider('expectedCrvProvider')]
    public function testExpectedCrv(Algorithm $algorithm, ?string $expected): void
    {
        self::assertSame($expected, $algorithm->expectedCrv());
    }

    /** @return array<int, array{Algorithm, string|null}> */
    public static function expectedCrvProvider(): array
    {
        return [
            [Algorithm::RS256, null],
            [Algorithm::RS384, null],
            [Algorithm::RS512, null],
            [Algorithm::ES256, 'P-256'],
            [Algorithm::ES384, 'P-384'],
            [Algorithm::ES512, 'P-521'],
        ];
    }

    public function testFromValue(): void
    {
        self::assertSame(Algorithm::RS256, Algorithm::from('RS256'));
        self::assertSame(Algorithm::ES256, Algorithm::from('ES256'));
        self::assertNull(Algorithm::tryFrom('INVALID'));
    }
}
