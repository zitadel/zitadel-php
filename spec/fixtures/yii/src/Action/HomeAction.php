<?php

declare(strict_types=1);

namespace App\Action;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Zitadel\Sdk\Attribute\AllowAnonymous;

// Note: AllowAnonymous has no runtime effect here — the PSR-15 ZitadelMiddleware runs
// before Yii's router resolves the action, so the RouteResult attribute is not yet set.
// /home is added to ignoredRoutes in di.php instead, which achieves the same outcome.
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
