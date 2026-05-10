<?php

declare(strict_types=1);

namespace Zitadel\Sdk\Auth;

use Zitadel\Sdk\Config\ZitadelConfig;
use Zitadel\Sdk\Exception\PkceException;

/**
 * Static helpers for the OAuth 2.0 PKCE (Proof Key for Code Exchange) flow.
 *
 * All methods are pure functions with no instance state. The class cannot be
 * instantiated.
 *
 * @see https://www.rfc-editor.org/rfc/rfc7636
 */
final class PkceFlow
{
    private function __construct()
    {
    }

    /**
     * Generates a cryptographically random code verifier.
     *
     * Uses `random_bytes(32)` → base64url-encoded without padding → exactly 43
     * characters, satisfying RFC 7636 §4.1 (43–128 characters, unreserved set).
     * 32 bytes = 256 bits of entropy.
     */
    public static function generateCodeVerifier(): string
    {
        return rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
    }

    /**
     * Generates a cryptographically random CSRF state value.
     *
     * Uses `random_bytes(32)` → base64url-encoded → 43 characters, 256-bit entropy.
     * Used to prevent CSRF attacks in the authorization code flow.
     */
    public static function generateState(): string
    {
        return rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
    }

    /**
     * Derives the S256 code challenge from a code verifier.
     *
     * Computes `BASE64URL(SHA-256(ASCII(code_verifier)))` per RFC 7636 §4.2.
     *
     * @param string $verifier Code verifier produced by {@see generateCodeVerifier()}.
     */
    public static function generateCodeChallenge(string $verifier): string
    {
        return rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
    }

    /**
     * Builds the Zitadel authorization URL for the PKCE redirect.
     *
     * Includes `response_type=code`, `code_challenge_method=S256`, the
     * provided challenge and state, and the scopes from config.
     *
     * @param ZitadelConfig $config    Middleware configuration.
     * @param string        $challenge Code challenge from {@see generateCodeChallenge()}.
     * @param string        $state     Random CSRF state value.
     */
    public static function buildAuthorizationUrl(
        ZitadelConfig $config,
        string $challenge,
        string $state,
    ): string {
        $params = http_build_query([
            'response_type'         => 'code',
            'client_id'             => $config->clientId,
            'redirect_uri'          => $config->redirectUri,
            'scope'                 => implode(' ', $config->scopes),
            'code_challenge'        => $challenge,
            'code_challenge_method' => 'S256',
            'state'                 => $state,
        ]);

        return $config->authorizationEndpoint() . '?' . $params;
    }

    /**
     * Exchanges an authorization code for tokens at the Zitadel token endpoint.
     *
     * Makes a cURL POST to `config->tokenEndpoint()` with `grant_type=authorization_code`,
     * the received code, the PKCE verifier, client ID, and redirect URI.
     *
     * @param ZitadelConfig $config   Middleware configuration.
     * @param string        $code     Authorization code from the callback query string.
     * @param string        $verifier Code verifier from the PKCE state cookie.
     * @return array<string, mixed>
     * @throws PkceException When the HTTP request fails, the response body is not valid
     *   JSON, or the response contains an OAuth error field.
     */
    public static function exchangeCode(
        ZitadelConfig $config,
        string $code,
        string $verifier,
    ): array {
        $ch = curl_init($config->tokenEndpoint());
        if ($ch === false) {
            throw new PkceException('[zitadel] Failed to initialise cURL for token exchange.');
        }

        curl_setopt_array($ch, [
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => http_build_query([
                'grant_type'    => 'authorization_code',
                'code'          => $code,
                'redirect_uri'  => $config->redirectUri,
                'client_id'     => $config->clientId,
                'code_verifier' => $verifier,
            ]),
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => $config->httpTimeoutSeconds,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_HTTPHEADER     => ['Content-Type: application/x-www-form-urlencoded'],
        ]);

        $body  = curl_exec($ch);
        $errno = curl_errno($ch);
        $error = curl_error($ch);

        if ($errno !== 0 || $body === false) {
            throw new PkceException("[zitadel] Token exchange request failed: {$error} (errno {$errno})");
        }

        /** @var string $body */
        if (!json_validate($body)) {
            throw new PkceException('[zitadel] Token exchange returned non-JSON response.');
        }

        /** @var array<string, mixed> $data */
        $data = json_decode($body, true);

        if (isset($data['error'])) {
            $desc = $data['error_description'] ?? $data['error'];
            throw new PkceException("[zitadel] Token exchange OAuth error: {$desc}");
        }

        return $data;
    }
}
