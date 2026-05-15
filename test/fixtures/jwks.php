<?php

declare(strict_types=1);

/**
 * Minimal JWKS server for JwksCache integration tests.
 *
 * Generates a fresh RSA-2048 key pair on startup and serves it as a JWKS JSON
 * response. The key material is deterministic within a single server process
 * so callers can verify signatures against the public key if needed.
 *
 * Response: `{"keys": [{"kty": "RSA", "kid": "test-key", "use": "sig", "n": "...", "e": "..."}]}`
 */

$key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
assert($key !== false);

$details = openssl_pkey_get_details($key);
assert($details !== false);

$n = rtrim(strtr(base64_encode($details['rsa']['n']), '+/', '-_'), '=');
$e = rtrim(strtr(base64_encode($details['rsa']['e']), '+/', '-_'), '=');

$kid = $_GET['kid'] ?? 'test-key';

header('Content-Type: application/json');

echo json_encode([
    'keys' => [
        [
            'kty' => 'RSA',
            'kid' => $kid,
            'use' => 'sig',
            'alg' => 'RS256',
            'n'   => $n,
            'e'   => $e,
        ],
    ],
]);
