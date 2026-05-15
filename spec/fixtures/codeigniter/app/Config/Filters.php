<?php

declare(strict_types=1);

namespace Config;

use CodeIgniter\Config\BaseConfig;
use Zitadel\Sdk\Bridge\CodeIgniter\ZitadelFilter;

class Filters extends BaseConfig
{
    public array $aliases = [
        'zitadel' => ZitadelFilter::class,
    ];

    public array $globals = [
        'before' => ['zitadel'],
        'after'  => [],
    ];

    public array $methods = [];
    public array $filters = [];
}
