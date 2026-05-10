<?php

declare(strict_types=1);

namespace App\Action;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Zitadel\Sdk\Auth\Claims;

final class DashboardAction
{
    public function __invoke(
        ServerRequestInterface $request,
        ResponseInterface      $response,
    ): ResponseInterface {
        /** @var Claims|null $claims */
        $claims = $request->getAttribute('zitadel.claims');

        $response->getBody()->write("Hello {$claims?->name}");

        return $response->withHeader('Content-Type', 'text/plain');
    }
}
