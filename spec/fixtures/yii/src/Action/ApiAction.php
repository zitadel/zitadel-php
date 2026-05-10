<?php

declare(strict_types=1);

namespace App\Action;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Zitadel\Sdk\Attribute\AllowAnonymous;
use Zitadel\Sdk\Auth\Claims;

// Note: AllowAnonymous has no runtime effect for Yii's middleware order, but a valid
// Bearer token is still validated at step 5 (token extraction) before the attribute
// check — so JWKS-based Bearer validation works correctly regardless.
#[AllowAnonymous]
final class ApiAction
{
    public function __invoke(
        ServerRequestInterface $request,
        ResponseInterface      $response,
    ): ResponseInterface {
        /** @var Claims|null $claims */
        $claims  = $request->getAttribute('zitadel.claims');
        $payload = $claims !== null
            ? ['authenticated' => true, 'sub' => $claims->sub, 'name' => $claims->name, 'email' => $claims->email]
            : ['authenticated' => false];

        $response->getBody()->write((string) json_encode($payload));

        return $response->withHeader('Content-Type', 'application/json');
    }
}
