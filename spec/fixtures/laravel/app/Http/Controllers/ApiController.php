<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Zitadel\Sdk\Attribute\AllowAnonymous;
use Zitadel\Sdk\Bridge\Laravel\Auth\ZitadelUser;

#[AllowAnonymous]
final class ApiController
{
    public function __invoke(): JsonResponse
    {
        /** @var ZitadelUser|null $user */
        $user = auth('zitadel')->user();

        if ($user !== null) {
            return response()->json([
                'authenticated' => true,
                'sub'           => $user->claims->sub,
                'name'          => $user->claims->name,
                'email'         => $user->claims->email,
            ]);
        }

        return response()->json(['authenticated' => false]);
    }
}
