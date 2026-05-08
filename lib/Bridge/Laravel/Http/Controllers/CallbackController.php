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
    public function __construct(
        private ZitadelConfig  $config,
        private TokenValidator $validator,
    ) {}

    public function __invoke(Request $request): RedirectResponse|Response
    {
        $pkceValue = $request->cookie('__nextgen_pkce');
        if (!is_string($pkceValue)) {
            return $this->badRequest('Authentication failed — PKCE state cookie missing. Please try signing in again.');
        }

        $pkce = PkceStateCookie::decrypt($pkceValue, $this->config->cookieSecret);
        if ($pkce === null) {
            return $this->badRequest('Authentication failed — PKCE state cookie invalid. Please try signing in again.');
        }

        $state = $request->query('state');
        if ($state !== $pkce['state']) {
            return $this->badRequest('Authentication failed — state parameter mismatch. Please try signing in again.');
        }

        $code = $request->query('code');
        if (!is_string($code) || $code === '') {
            $oauthError = $request->query('error_description') ?? $request->query('error') ?? 'Missing code';
            return $this->badRequest("Authentication failed — {$oauthError}. Please try signing in again.");
        }

        try {
            $tokens = PkceFlow::exchangeCode($this->config, $code, $pkce['verifier']);
        } catch (PkceException $e) {
            return $this->badRequest('Authentication failed — token exchange error: ' . $e->getMessage());
        }

        $accessToken = $tokens['access_token'] ?? null;
        if (!is_string($accessToken)) {
            return $this->badRequest('Authentication failed — no access token in response.');
        }

        $claims = $this->validator->validate($accessToken);
        if ($claims === null) {
            return $this->badRequest('Authentication failed — could not validate the token received from the identity provider.');
        }

        $next   = $this->sanitizeNext($pkce['next']) ?? $this->config->postLoginRedirect;
        $maxAge = max(0, $claims->exp - time());
        $secure = $request->isSecure();

        $response = redirect($next);
        $response->cookie(
            '__nextgen_auth',
            $accessToken,
            $maxAge / 60,
            '/',
            null,
            $secure,
            true,
            false,
            'lax'
        );

        // Delete the PKCE state cookie
        $response->withCookie(cookie()->forget('__nextgen_pkce', '/'));

        return $response;
    }

    private function sanitizeNext(string $next): ?string
    {
        if (!str_starts_with($next, '/') || str_starts_with($next, '//')) {
            return null;
        }

        if (str_contains($next, '\\')) {
            return null;
        }

        if (parse_url($next, PHP_URL_SCHEME) !== null) {
            return null;
        }

        return $next;
    }

    private function badRequest(string $message): Response
    {
        $html = '<!DOCTYPE html><html><head><title>Authentication Error</title></head><body>'
            . '<h1>Authentication Error</h1><p>' . htmlspecialchars($message, ENT_QUOTES, 'UTF-8') . '</p>'
            . '<p><a href="javascript:history.back()">Go back</a></p>'
            . '</body></html>';

        return response($html, 400)->header('Content-Type', 'text/html; charset=utf-8');
    }
}
