<?php

declare(strict_types=1);

namespace Zitadel\Sdk\Exception;

/**
 * Thrown when JWT token validation fails in a context where a hard failure is
 * preferred over returning null (e.g. explicit validation calls outside the
 * middleware). The middleware itself catches this and returns null to callers.
 */
final class TokenValidationException extends \RuntimeException
{
    public function __construct(string $message, int $code = 0, ?\Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
}
