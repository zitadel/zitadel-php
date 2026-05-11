<?php

declare(strict_types=1);

namespace App\Controller;

use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Zitadel\Sdk\Attribute\AllowAnonymous;
use Zitadel\Sdk\Auth\Claims;

final class DashboardController
{
    #[Route('/dashboard')]
    public function index(?Claims $claims): Response
    {
        return new Response("Hello {$claims?->name}\nemail:{$claims?->email}\nsub:{$claims?->sub}");
    }

    #[Route('/health')]
    #[AllowAnonymous]
    public function health(): Response
    {
        return new Response('OK');
    }

    #[Route('/home')]
    #[AllowAnonymous]
    public function home(): Response
    {
        return new Response('Welcome home');
    }

    #[Route('/api')]
    #[AllowAnonymous]
    public function api(?Claims $claims): JsonResponse
    {
        if ($claims !== null) {
            return new JsonResponse([
                'authenticated' => true,
                'sub'           => $claims->sub,
                'name'          => $claims->name,
                'email'         => $claims->email,
            ]);
        }

        return new JsonResponse(['authenticated' => false]);
    }
}
