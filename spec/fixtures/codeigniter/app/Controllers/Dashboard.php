<?php

declare(strict_types=1);

namespace App\Controllers;

use CodeIgniter\Controller;
use Zitadel\Sdk\Bridge\CodeIgniter\ZitadelHolder;

final class Dashboard extends Controller
{
    public function index(): string
    {
        $claims = ZitadelHolder::claims();

        return "Hello {$claims?->name}\nemail:{$claims?->email}\nsub:{$claims?->sub}";
    }
}
