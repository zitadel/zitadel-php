<?php

declare(strict_types=1);

use Phalcon\Mvc\Controller;
use Zitadel\Sdk\Auth\Claims;

class DashboardController extends Controller
{
    public function indexAction(): string
    {
        /** @var Claims|null $claims */
        $claims = $this->di->get('zitadel.claims');

        return "Hello {$claims?->name}\nemail:{$claims?->email}\nsub:{$claims?->sub}";
    }
}
