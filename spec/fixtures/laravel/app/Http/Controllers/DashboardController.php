<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use Illuminate\Http\Response;

final class DashboardController
{
    public function __invoke(): Response
    {
        /** @var \Zitadel\Sdk\Bridge\Laravel\Auth\ZitadelUser $user */
        $user = auth('zitadel')->user();

        return response("Hello {$user->claims->name}\nemail:{$user->claims->email}\nsub:{$user->claims->sub}");
    }
}
