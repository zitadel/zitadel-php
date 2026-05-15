<?php

declare(strict_types=1);

/**
 * Minimal echo server for HttpProxy integration tests.
 *
 * Returns the request method, path, headers, and body as JSON so tests can
 * verify exactly what HttpProxy::forward() sends to the upstream.
 *
 * Special behaviour: if the request includes `X-Echo-Cookies: N`, the response
 * emits N `Set-Cookie` headers so tests can verify multi-cookie isolation.
 */

$headers = [];

foreach ($_SERVER as $key => $value) {
    if (str_starts_with($key, 'HTTP_')) {
        $name           = strtolower(str_replace('_', '-', substr($key, 5)));
        $headers[$name] = (string) $value;
    }
}

// PHP does not prefix CONTENT_TYPE / CONTENT_LENGTH with HTTP_
if (isset($_SERVER['CONTENT_TYPE']) && (string) $_SERVER['CONTENT_TYPE'] !== '') {
    $headers['content-type'] = (string) $_SERVER['CONTENT_TYPE'];
}

if (isset($_SERVER['CONTENT_LENGTH']) && (string) $_SERVER['CONTENT_LENGTH'] !== '') {
    $headers['content-length'] = (string) $_SERVER['CONTENT_LENGTH'];
}

// Emit N Set-Cookie headers when requested so the caller can verify
// that HttpProxy::forward() collects each one separately.
if (isset($headers['x-echo-cookies'])) {
    $count = max(0, (int) $headers['x-echo-cookies']);

    for ($i = 1; $i <= $count; $i++) {
        header("Set-Cookie: __nextgen_cookie{$i}=val{$i}; HttpOnly; SameSite=Lax", false);
    }
}

header('Content-Type: application/json');

echo json_encode([
    'method'  => $_SERVER['REQUEST_METHOD'],
    'path'    => $_SERVER['REQUEST_URI'],
    'headers' => $headers,
    'body'    => (string) file_get_contents('php://input'),
]);
