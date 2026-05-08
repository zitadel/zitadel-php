<?php

declare(strict_types=1);

namespace Zitadel\Sdk\Bridge\Laravel\Http\Controllers;

use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Zitadel\Sdk\Config\ZitadelConfig;

/**
 * Clears the session cookie and redirects to Zitadel's end-session endpoint.
 *
 * Registered internally by {@see \Zitadel\Sdk\Bridge\Laravel\ZitadelServiceProvider}
 * via `loadRoutesFrom()`. No user-land route definition is needed.
 *
 * Logout with no active session silently redirects to `$postLogoutRedirect` —
 * never returns 400.
 */
readonly class LogoutController
{
    public function __construct(private ZitadelConfig $config)
    {
    }

    public function __invoke(Request $request): RedirectResponse
    {
        $params = http_build_query([
            'post_logout_redirect_uri' => $this->config->postLogoutRedirect,
        ]);

        $response = redirect($this->config->endSessionEndpoint() . '?' . $params);
        $response->withCookie(cookie()->forget('__nextgen_auth', '/'));

        return $response;
    }
}
