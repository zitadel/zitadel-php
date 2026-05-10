<?php

declare(strict_types=1);

namespace App\Controllers;

use CodeIgniter\Controller;
use Zitadel\Sdk\Attribute\AllowAnonymous;

#[AllowAnonymous]
final class Home extends Controller
{
    public function index(): string
    {
        return 'Welcome home';
    }
}
