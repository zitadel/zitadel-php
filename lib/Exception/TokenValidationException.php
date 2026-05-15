<?php

declare(strict_types=1);

namespace Zitadel\Sdk\Exception;

/**
 * Thrown when JWT token validation fails in a context where a hard failure is
 * preferred over receiving null (e.g. an application-level validation helper that
 * wraps {@see \Zitadel\Sdk\Auth\TokenValidator::validate()}).
 *
 * The middleware bridges do NOT throw this exception internally — they return null
 * on validation failure. This class is provided for application code that wants to
 * signal a validation error through the exception mechanism.
 */
final class TokenValidationException extends \RuntimeException
{
    /**
     * @param string          $message  Human-readable description of the validation failure.
     *                                  Should be prefixed with `[zitadel]` for easy log grepping.
     * @param int             $code     Optional numeric error code (defaults to 0).
     * @param \Throwable|null $previous Optional underlying cause.
     */
    public function __construct(string $message, int $code = 0, ?\Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
}
