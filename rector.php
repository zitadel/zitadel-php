<?php

/** @noinspection PhpUnused */

use Rector\Config\RectorConfig;
use Rector\Set\ValueObject\LevelSetList;

return static function (RectorConfig $rectorConfig): void {
    $rectorConfig->paths(array_merge(
        [__DIR__ . '/lib', __DIR__ . '/test'],
        glob(__DIR__ . '/spec/*.php') ?: [],
    ));

    $rectorConfig->sets([
        LevelSetList::UP_TO_PHP_80,
    ]);
};
