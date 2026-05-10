<?php

declare(strict_types=1);

namespace Config;

use CodeIgniter\Config\BaseConfig;
use App\Filters\ZitadelFilterWrapper;

class Filters extends BaseConfig
{
    public array $aliases = [
        'zitadel' => ZitadelFilterWrapper::class,
    ];

    public array $globals = [
        'before' => ['zitadel'],
        'after'  => [],
    ];

    public array $methods = [];
    public array $filters = [];
}
