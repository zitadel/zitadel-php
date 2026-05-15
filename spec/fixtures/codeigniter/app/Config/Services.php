<?php

declare(strict_types=1);

namespace Config;

use CodeIgniter\Config\Services as BaseServices;

/**
 * No Zitadel-specific service factories needed here.
 *
 * ZitadelFilter self-configures from config('Zitadel') — it reads
 * app/Config/Zitadel.php (or the SDK base class defaults) and builds
 * its own ZitadelConfig and TokenValidator internally. No zitadelConfig()
 * or zitadelValidator() factories are required for standard usage.
 */
class Services extends BaseServices
{
}
