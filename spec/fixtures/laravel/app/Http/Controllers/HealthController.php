<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use Illuminate\Http\Response;
use Zitadel\Sdk\Attribute\AllowAnonymous;

#[AllowAnonymous]
final class HealthController
{
    public function __invoke(): Response
    {
        return response('OK', 200);
    }
}
