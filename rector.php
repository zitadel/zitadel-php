<?php

/** @noinspection PhpUnused */

use Rector\Config\RectorConfig;
use Rector\Php81\Rector\Property\ReadOnlyPropertyRector;
use Rector\Php82\Rector\Class_\ReadOnlyClassRector;
use Rector\Set\ValueObject\LevelSetList;

return static function (RectorConfig $rectorConfig): void {
    $rectorConfig->paths(array_merge(
        [__DIR__ . '/lib', __DIR__ . '/test'],
        glob(__DIR__ . '/spec/*.php') ?: [],
    ));

    $rectorConfig->sets([
        LevelSetList::UP_TO_PHP_80,
    ]);

    // ── Immutability enforcement ────────────────────────────────────────────
    // These rules ensure value objects, config, and utility classes remain
    // immutable. Rector will auto-promote eligible classes to readonly.

    // PHP 8.1: promote non-promoted properties declared and assigned in __construct
    // to `readonly` property declarations.
    // PHP 8.2: promote classes where every property is readonly to `readonly class`.
    // Prevents accidental mutation from being introduced by future contributors.
    $rectorConfig->rules([
        ReadOnlyPropertyRector::class,
        ReadOnlyClassRector::class,
    ]);
};
