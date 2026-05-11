<?php

declare(strict_types=1);

namespace App\Action;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Zitadel\Sdk\Attribute\AllowAnonymous;

#[AllowAnonymous]
final class HomeAction
{
    public function __invoke(
        ServerRequestInterface $request,
        ResponseInterface      $response,
    ): ResponseInterface {
        $response->getBody()->write('Welcome home');

        return $response->withHeader('Content-Type', 'text/plain');
    }
}
