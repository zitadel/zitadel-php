<?php

declare(strict_types=1);

namespace Config;

use CodeIgniter\Config\BaseConfig;

class App extends BaseConfig
{
    public string $baseURL = 'http://localhost:9004/';
    public string $indexPage = '';
    public string $uriProtocol = 'REQUEST_URI';
    public string $defaultLocale = 'en';
    public bool   $negotiateLocale = false;
    public array  $supportedLocales = ['en'];
    public string $appTimezone = 'UTC';
    public string $charset = 'UTF-8';
    public bool   $forceGlobalSecureRequests = false;
    public array  $proxyIPs = [];
    public array  $allowedHostnames = [];
    public string $cookiePrefix   = '';
    public string $cookieDomain   = '';
    public string $cookiePath     = '/';
    public bool   $cookieSecure   = false;
    public bool   $cookieHTTPOnly = false;
    public string $cookieSameSite = 'Lax';
    public bool   $CSPEnabled = false;
}
