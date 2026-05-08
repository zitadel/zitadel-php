<?php

declare(strict_types=1);

namespace App\Controller;

use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Zitadel\Sdk\Auth\Claims;

final class DashboardController
{
    #[Route('/dashboard')]
    public function index(?Claims $claims): Response
    {
        return new Response("Hello {$claims?->name}");
    }

    #[Route('/health')]
    public function health(): Response
    {
        return new Response('OK');
    }
}
