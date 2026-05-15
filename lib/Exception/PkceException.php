<?php

declare(strict_types=1);

namespace Zitadel\Sdk\Exception;

/**
 * Thrown when the PKCE authorization code exchange fails — either due to an
 * HTTP error, a malformed response, or an OAuth error response from the server.
 *
 * RFC 6749 §5.2 error responses (`{"error":"...","error_description":"..."}`) are
 * inspected; the `error_description` is included in the message for debuggability.
 */
final class PkceException extends \RuntimeException
{
    /**
     * @param string         $message  Human-readable description of the PKCE failure. Should be
     *                                 prefixed with `[zitadel]` for easy log grepping.
     * @param int            $code     Optional numeric error code (defaults to 0).
     * @param \Throwable|null $previous Optional underlying cause.
     */
    public function __construct(string $message, int $code = 0, ?\Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
}
