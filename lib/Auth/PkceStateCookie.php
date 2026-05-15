<?php

declare(strict_types=1);

namespace Zitadel\Sdk\Auth;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Manages the `__nextgen_pkce` cookie used to carry PKCE state across the
 * authorization redirect.
 *
 * The cookie payload is a JSON object `{verifier, state, next}` encrypted with
 * XChaCha20-Poly1305 via {@see sodium_crypto_aead_xchacha20poly1305_ietf_encrypt()}.
 * A 24-byte random nonce is prepended to the ciphertext and the result is
 * base64url-encoded. The encryption key is {@see \Zitadel\Sdk\Config\ZitadelConfig::$cookieSecret}.
 *
 * ## Cookie API layers
 *
 * - **Lower layer** (`encrypt`/`decrypt`) — pure string I/O; no HTTP objects.
 *   Used by Laravel (`CallbackController`), Symfony (`ZitadelListener`), and
 *   CodeIgniter (`ZitadelFilter`), which set/read cookies via their own framework
 *   cookie API.
 * - **Upper layer** (`write`/`read`/`delete`) — PSR-7 `ResponseInterface`/
 *   `ServerRequestInterface` wrappers used by the PSR-15 core middleware and the
 *   Yii 3 bridge.
 * - **Phalcon** bridges bypass `PkceStateCookie` entirely and build raw `Set-Cookie`
 *   header strings directly to work around Phalcon's replace-semantics header API.
 *
 * All methods are static; the class cannot be instantiated.
 */
final class PkceStateCookie
{
    private function __construct()
    {
    }

    private const string COOKIE_NAME = '__nextgen_pkce';
    private const int COOKIE_TTL = 600;

    /**
     * Encrypts a PKCE state payload into a base64url-encoded cookie value string.
     *
     * @param string $verifier PKCE code verifier.
     * @param string $state    Random CSRF state value.
     * @param string $next     Full request URI the user was navigating to (path + query).
     *                          Must start with `/` and not start with `//`.
     * @param string $secret   Cookie encryption key (64-char hex string → 32 raw bytes).
     * @return string Base64url-encoded `nonce || ciphertext` string.
     * @throws \InvalidArgumentException When `$secret` is not a valid 64-character hex string.
     */
    public static function encrypt(
        string $verifier,
        string $state,
        string $next,
        #[\SensitiveParameter] string $secret,
    ): string {
        if (!self::isValidHex($secret)) {
            throw new \InvalidArgumentException('[zitadel] cookieSecret is not valid hex.');
        }

        /** @var string $key */
        $key      = hex2bin($secret);
        $nonce    = random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
        $payload  = json_encode(['verifier' => $verifier, 'state' => $state, 'next' => $next]);
        $cipher   = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
            (string) $payload,
            '',
            $nonce,
            $key
        );

        return rtrim(strtr(base64_encode($nonce . $cipher), '+/', '-_'), '=');
    }

    /**
     * Decrypts a raw `__nextgen_pkce` cookie value produced by {@see encrypt()}.
     *
     * Returns null when the value is absent, cannot be decrypted (wrong key,
     * tampered ciphertext), or contains a malformed payload.
     *
     * @param string $cookieValue Raw cookie value string (base64url-encoded).
     * @param string $secret      Cookie encryption key (64-char hex string → 32 raw bytes).
     * @return array{verifier: string, state: string, next: string}|null
     * @throws \InvalidArgumentException When `$secret` is not a valid 64-character hex string.
     */
    public static function decrypt(
        #[\SensitiveParameter] string $cookieValue,
        #[\SensitiveParameter] string $secret,
    ): ?array {
        $raw = base64_decode(strtr($cookieValue, '-_', '+/') . str_repeat('=', (4 - strlen($cookieValue) % 4) % 4));
        if ($raw === false || strlen($raw) <= SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES) {
            return null;
        }

        $nonce  = substr($raw, 0, SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
        $cipher = substr($raw, SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
        if (!self::isValidHex($secret)) {
            throw new \InvalidArgumentException('[zitadel] cookieSecret is not valid hex.');
        }

        /** @var string $key */
        $key = hex2bin($secret);

        try {
            $plain = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($cipher, '', $nonce, $key);
        } catch (\SodiumException) {
            return null;
        }

        if ($plain === false || !json_validate($plain)) {
            return null;
        }

        $data = json_decode($plain, true);
        if (
            !is_array($data) ||
            !isset($data['verifier'], $data['state'], $data['next']) ||
            !is_string($data['verifier']) ||
            !is_string($data['state']) ||
            !is_string($data['next'])
        ) {
            return null;
        }

        return ['verifier' => $data['verifier'], 'state' => $data['state'], 'next' => $data['next']];
    }

    /**
     * Attaches the `__nextgen_pkce` cookie to a PSR-7 response.
     *
     * @param ResponseInterface $response PSR-7 response to add the cookie to.
     * @param string            $verifier PKCE code verifier.
     * @param string            $state    Random CSRF state value.
     * @param string            $next     Original URL the user was navigating to.
     * @param string            $secret   Cookie encryption key.
     * @param bool              $secure   Whether to set the Secure flag.
     * @return ResponseInterface New response with `Set-Cookie` header added.
     */
    public static function write(
        ResponseInterface $response,
        string $verifier,
        string $state,
        string $next,
        string $secret,
        bool $secure,
    ): ResponseInterface {
        $value  = self::encrypt($verifier, $state, $next, $secret);
        $cookie = self::COOKIE_NAME . '=' . $value
            . '; Max-Age=' . self::COOKIE_TTL
            . '; Path=/'
            . '; HttpOnly'
            . '; SameSite=Lax'
            . ($secure ? '; Secure' : '');

        return $response->withAddedHeader('Set-Cookie', $cookie);
    }

    /**
     * Reads and decrypts the `__nextgen_pkce` cookie from a PSR-7 request.
     *
     * @param ServerRequestInterface $request PSR-7 request carrying the cookie.
     * @param string                 $secret  Cookie encryption key.
     * @return array{verifier: string, state: string, next: string}|null
     * @throws \InvalidArgumentException When `$secret` is not a valid 64-character hex string.
     */
    public static function read(
        ServerRequestInterface $request,
        string $secret,
    ): ?array {
        $cookies = $request->getCookieParams();
        $value   = $cookies[self::COOKIE_NAME] ?? null;

        return $value !== null ? self::decrypt($value, $secret) : null;
    }

    /**
     * Returns a PSR-7 response with the `__nextgen_pkce` cookie deleted.
     *
     * @param ResponseInterface $response PSR-7 response to add the deletion header to.
     * @return ResponseInterface New response with deletion `Set-Cookie` header.
     */
    public static function delete(ResponseInterface $response): ResponseInterface
    {
        return $response->withAddedHeader(
            'Set-Cookie',
            self::COOKIE_NAME . '=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax'
        );
    }

    /**
     * Returns true when `$hex` is a non-empty even-length string of hex digits.
     *
     * Pre-validating before calling `hex2bin()` avoids the PHP warning that
     * `hex2bin()` emits for invalid input before returning `false`.
     */
    private static function isValidHex(string $hex): bool
    {
        return $hex !== '' && strlen($hex) % 2 === 0 && ctype_xdigit($hex);
    }
}
