<?php

declare(strict_types=1);

use Phalcon\Mvc\Controller;
use Zitadel\Sdk\Attribute\AllowAnonymous;

#[AllowAnonymous]
class HealthController extends Controller
{
    public function indexAction(): string
    {
        return 'OK';
    }
}
