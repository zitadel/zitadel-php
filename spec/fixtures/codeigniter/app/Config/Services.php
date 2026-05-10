<?php

declare(strict_types=1);

namespace Config;

use CodeIgniter\Config\Services as BaseServices;
use Zitadel\Sdk\Auth\JwksCache;
use Zitadel\Sdk\Auth\TokenValidator;
use Zitadel\Sdk\Config\ZitadelConfig;

class Services extends BaseServices
{
    public static function zitadelConfig(bool $getShared = true): ZitadelConfig
    {
        if ($getShared) {
            return static::getSharedInstance('zitadelConfig');
        }

        return new ZitadelConfig(
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
        );
    }

    public static function zitadelValidator(bool $getShared = true): TokenValidator
    {
        if ($getShared) {
            return static::getSharedInstance('zitadelValidator');
        }

        $config = static::zitadelConfig(false);

        return new TokenValidator($config, new JwksCache());
    }
}
