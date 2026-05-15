<?php

declare(strict_types=1);

use Phalcon\Di\FactoryDefault;
use Phalcon\Mvc\View;
use Zitadel\Sdk\Bridge\Phalcon\ZitadelServiceProvider;
use Zitadel\Sdk\Config\ZitadelConfig;

$di = new FactoryDefault();

// Minimal view service (prevents "Phalcon\Mvc\View service must be set" error)
$di->set('view', fn () => new View(), true);

// Router
$di->set('router', function () {
    return require __DIR__ . '/router.php';
}, true);

// Zitadel SDK — registers zitadelConfig, zitadelValidator, and zitadelPlugin
ZitadelServiceProvider::register($di, new ZitadelConfig(
    issuerUrl:         (string) ($_ENV['ZITADEL_ISSUER_URL']         ?? ''),
    clientId:          (string) ($_ENV['ZITADEL_CLIENT_ID']          ?? ''),
    redirectUri:       (string) ($_ENV['ZITADEL_REDIRECT_URI']       ?? ''),
    cookieSecret:      (string) ($_ENV['ZITADEL_COOKIE_SECRET']      ?? ''),
    protectAll:        true,
    ignoredRoutes:     ['/health'],
    jwksPath:          (string) ($_ENV['ZITADEL_JWKS_PATH']          ?? '/oauth/v2/keys'),
    authorizationPath: (string) ($_ENV['ZITADEL_AUTHORIZATION_PATH'] ?? '/oauth/v2/authorize'),
    tokenPath:         (string) ($_ENV['ZITADEL_TOKEN_PATH']         ?? '/oauth/v2/token'),
    endSessionPath:    (string) ($_ENV['ZITADEL_END_SESSION_PATH']   ?? '/oidc/v1/end_session'),
));

return $di;
