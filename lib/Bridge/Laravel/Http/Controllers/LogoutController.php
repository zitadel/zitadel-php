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
     * Deletes the `__nextgen_auth` cookie and any other stale `__nextgen*` cookies
     * (e.g. a leftover `__nextgen_pkce` from an abandoned login flow), then sends
     * the browser to the OIDC end-session endpoint with the configured
     * `post_logout_redirect_uri`. A missing or expired cookie is silently ignored —
     * logout always succeeds.
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

        $secure = $request->isSecure();

        // Always delete __nextgen_auth, even when it is absent from the request
        // (expired/already cleared), so the browser removes any remnant.
        // Pass $secure explicitly: cookie()->forget() relies on the CookieJar default
        // and may omit the Secure flag, which prevents browsers from deleting a
        // Secure-flagged cookie.
        $response = $response->withCookie(cookie('__nextgen_auth', '', -2628000, '/', null, $secure, true, false, 'lax'));

        // Also delete any other stale __nextgen* cookies present in the request
        // (e.g. __nextgen_pkce left over from an abandoned login flow).
        foreach ($request->cookies->keys() as $name) {
            $name = (string) $name;
            if (str_starts_with($name, '__nextgen') && $name !== '__nextgen_auth') {
                $response = $response->withCookie(cookie($name, '', -2628000, '/', null, $secure, true, false, 'lax'));
            }
        }

        return $response;
    }
}
