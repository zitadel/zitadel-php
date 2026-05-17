<?php

declare(strict_types=1);

namespace Zitadel\Sdk\Bridge\Laravel\Http\Controllers;

use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Zitadel\Sdk\Auth\PkceFlow;
use Zitadel\Sdk\Auth\PkceStateCookie;
use Zitadel\Sdk\Auth\TokenValidator;
use Zitadel\Sdk\Config\ZitadelConfig;
use Zitadel\Sdk\Event\ZitadelLoginEvent;
use Zitadel\Sdk\Exception\PkceException;

/**
 * Handles the OAuth 2.0 PKCE callback — validates state, exchanges the
 * authorization code for tokens, validates the access token, and sets
 * the session cookie before redirecting.
 *
 * Registered internally by {@see \Zitadel\Sdk\Bridge\Laravel\ZitadelServiceProvider}
 * via `loadRoutesFrom()`. No user-land route definition is needed.
 */
readonly class CallbackController
{
    /**
     * @param ZitadelConfig  $config    SDK configuration (issuer, cookie secret, redirect paths).
     * @param TokenValidator $validator JWT validator used to verify the access token after exchange.
     */
    public function __construct(
        private ZitadelConfig  $config,
        private TokenValidator $validator,
    ) {
    }

    /**
     * Handles the OAuth 2.0 PKCE callback.
     *
     * Validates the PKCE state cookie and `state` query parameter, exchanges the
     * authorization `code` for tokens, validates the resulting access token, sets
     * the `__nextgen_auth` session cookie, and redirects to the originally requested path.
     *
     * @param Request $request The callback request carrying `code` and `state` query params.
     * @return RedirectResponse|Response Redirect on success, or a 400 error response on failure.
     */
    public function __invoke(Request $request): RedirectResponse|Response
    {
        // Determine the Secure flag upfront — needed on every error path so that
        // the PKCE cookie deletion header matches the Secure attribute that was set
        // when the cookie was created. Browsers refuse to delete a Secure-flagged
        // cookie via a non-Secure Set-Cookie directive (RFC 6265bis §5.4).
        $secure = $request->isSecure();

        // Build a reusable deletion cookie for __nextgen_pkce. Using cookie() with
        // an explicit $secure argument guarantees the flag is correct regardless of
        // the CookieJar's global default (which cookie()->forget() would inherit).
        $deletePkce = cookie('__nextgen_pkce', '', -2628000, '/', null, $secure, true, false, 'lax');

        $pkceValue = $request->cookie('__nextgen_pkce');
        if (!is_string($pkceValue)) {
            return $this->badRequest('Authentication failed — PKCE state cookie missing. Please try signing in again.')
                ->withCookie($deletePkce);
        }

        $pkce = PkceStateCookie::decrypt($pkceValue, $this->config->cookieSecret);
        if ($pkce === null) {
            return $this->badRequest('Authentication failed — PKCE state cookie invalid. Please try signing in again.')
                ->withCookie($deletePkce);
        }

        $state = $request->query('state');
        if (!hash_equals($pkce['state'], (string) $state)) {
            return $this->badRequest('Authentication failed — state parameter mismatch. Please try signing in again.')
                ->withCookie($deletePkce);
        }

        $code = $request->query('code');
        if (!is_string($code) || $code === '') {
            $oauthError = $request->query('error_description') ?? $request->query('error') ?? 'Missing code';
            return $this->badRequest("Authentication failed — {$oauthError}. Please try signing in again.")
                ->withCookie($deletePkce);
        }

        try {
            $tokens = PkceFlow::exchangeCode($this->config, $code, $pkce['verifier']);
        } catch (PkceException) {
            return $this->badRequest('Authentication failed — the login server returned an error. Please try signing in again.')
                ->withCookie($deletePkce);
        }

        $tokenToValidate = PkceFlow::selectToken($tokens);
        if ($tokenToValidate === null) {
            return $this->badRequest('Authentication failed — no usable token in response.')
                ->withCookie($deletePkce);
        }

        $claims = $this->validator->validate($tokenToValidate);
        if ($claims === null) {
            return $this->badRequest('Authentication failed — could not validate the token received from the identity provider.')
                ->withCookie($deletePkce);
        }

        $next   = PkceFlow::sanitizeNext($pkce['next']) ?? $this->config->postLoginRedirect;
        $maxAge = max(0, $claims->exp - time());

        event(new ZitadelLoginEvent($claims));

        // Delete the PKCE state cookie and set the auth token cookie.
        // Both withCookie/cookie calls return a new response — chain them.
        return redirect($next)
            ->cookie(
                '__nextgen_auth',
                $tokenToValidate,
                (int) ceil($maxAge / 60),
                '/',
                null,
                $secure,
                true,
                false,
                'lax'
            )
            ->withCookie($deletePkce);
    }

    /**
     * Builds a 400 Bad Request HTML error response with a human-readable message.
     *
     * @param string $message The authentication error description shown to the user.
     * @return Response A 400 response with `Content-Type: text/html; charset=utf-8`.
     */
    private function badRequest(string $message): Response
    {
        $html = '<!DOCTYPE html><html><head><title>Authentication Error</title></head><body>'
            . '<h1>Authentication Error</h1><p>' . htmlspecialchars($message, ENT_QUOTES, 'UTF-8') . '</p>'
            . '<p><a href="javascript:history.back()">Go back</a></p>'
            . '</body></html>';

        return response($html, 400)->header('Content-Type', 'text/html; charset=utf-8');
    }
}
