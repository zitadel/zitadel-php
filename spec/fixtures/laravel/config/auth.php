<?php

declare(strict_types=1);

return [
    'defaults' => [
        'guard'     => 'zitadel',
        'passwords' => 'users',
    ],

    'guards' => [
        'zitadel' => [
            'driver' => 'zitadel',
        ],
    ],

    'providers' => [],
    'passwords' => [],
];
