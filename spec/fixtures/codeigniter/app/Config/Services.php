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

        /** @var \Config\Zitadel $cfg */
        $cfg = config('Zitadel');

        return new ZitadelConfig(
            issuerUrl:          $cfg->issuerUrl,
            clientId:           $cfg->clientId,
            redirectUri:        $cfg->redirectUri,
            cookieSecret:       $cfg->cookieSecret,
            protectAll:         $cfg->protectAll,
            ignoredRoutes:      $cfg->ignoredRoutes,
            protectedRoutes:    $cfg->protectedRoutes,
            callbackPath:       $cfg->callbackPath,
            logoutPath:         $cfg->logoutPath,
            proxyPath:          $cfg->proxyPath,
            postLoginRedirect:  $cfg->postLoginRedirect,
            postLogoutRedirect: $cfg->postLogoutRedirect,
            jwksPath:           $cfg->jwksPath,
            authorizationPath:  $cfg->authorizationPath,
            tokenPath:          $cfg->tokenPath,
            endSessionPath:     $cfg->endSessionPath,
            scopes:             $cfg->scopes,
            allowedAlgorithms:  $cfg->allowedAlgorithms,
            allowedTokenTypes:  $cfg->allowedTokenTypes,
            audience:           $cfg->audience,
            clockSkewSeconds:   $cfg->clockSkewSeconds,
            jwksTtlSeconds:     $cfg->jwksTtlSeconds,
            httpTimeoutSeconds: $cfg->httpTimeoutSeconds,
        );
    }

    public static function zitadelValidator(bool $getShared = true): TokenValidator
    {
        if ($getShared) {
            return static::getSharedInstance('zitadelValidator');
        }

        return new TokenValidator(static::zitadelConfig(false), new JwksCache());
    }
}
