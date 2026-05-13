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
    /**
     * @param ZitadelConfig $config SDK configuration (end-session endpoint, post-logout redirect URI).
     */
    public function __construct(private ZitadelConfig $config)
    {
    }

    /**
     * Clears the session cookie and redirects to Zitadel's end-session endpoint.
     *
     * Deletes the `__nextgen_auth` cookie and sends the browser to the OIDC end-session
     * endpoint with the configured `post_logout_redirect_uri`. A missing or expired cookie
     * is silently ignored — logout always succeeds.
     *
     * @param Request $request The logout request (scheme is used for cookie Secure flag).
     * @return RedirectResponse Redirect to the OIDC end-session endpoint.
     */
    public function __invoke(Request $request): RedirectResponse
    {
        $params = http_build_query([
            'client_id'                => $this->config->clientId,
            'post_logout_redirect_uri' => $this->config->postLogoutAbsoluteUri(),
        ]);

        $response = redirect($this->config->endSessionEndpoint() . '?' . $params);

        return $response->withCookie(cookie()->forget('__nextgen_auth', '/'));
    }
}
