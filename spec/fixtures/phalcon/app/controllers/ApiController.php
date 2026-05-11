<?php

declare(strict_types=1);

use Phalcon\Mvc\Controller;
use Zitadel\Sdk\Auth\Claims;
use Zitadel\Sdk\Attribute\AllowAnonymous;

#[AllowAnonymous]
class ApiController extends Controller
{
    public function indexAction(): string
    {
        /** @var Claims|null $claims */
        $claims  = $this->di->has('zitadel.claims') ? $this->di->get('zitadel.claims') : null;
        $payload = $claims !== null
            ? ['authenticated' => true, 'sub' => $claims->sub, 'name' => $claims->name, 'email' => $claims->email]
            : ['authenticated' => false];

        $this->response->setContentType('application/json');

        return (string) json_encode($payload);
    }
}
