<?php

declare(strict_types=1);

namespace App\Controllers;

use CodeIgniter\Controller;
use Zitadel\Sdk\Attribute\AllowAnonymous;
use Zitadel\Sdk\Bridge\CodeIgniter\ZitadelHolder;

#[AllowAnonymous]
final class Api extends Controller
{
    public function index(): string
    {
        $claims  = ZitadelHolder::claims();
        $payload = $claims !== null
            ? ['authenticated' => true, 'sub' => $claims->sub, 'name' => $claims->name, 'email' => $claims->email]
            : ['authenticated' => false];

        $this->response->setContentType('application/json');

        return (string) json_encode($payload);
    }
}
