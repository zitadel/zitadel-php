<?php

declare(strict_types=1);

use Phalcon\Mvc\Controller;
use Zitadel\Sdk\Attribute\AllowAnonymous;

#[AllowAnonymous]
class HomeController extends Controller
{
    public function indexAction(): string
    {
        return 'Welcome home';
    }
}
