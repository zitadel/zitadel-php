<?php

declare(strict_types=1);

namespace Zitadel\Sdk\Auth;

/**
 * Accepted values for the JWT `typ` header claim.
 *
 * The `typ` header identifies the media type of the token. Zitadel issues
 * access tokens with `typ: at+JWT` (RFC 9068) and plain ID tokens with
 * `typ: JWT`. {@see \Zitadel\Sdk\Config\ZitadelConfig::$allowedTokenTypes} controls
 * which values are accepted; the default allows both.
 */
enum TokenType: string
{
    /** Plain JWT — typically used for ID tokens. */
    case JWT = 'JWT';

    /** OAuth 2.0 Access Token JWT (RFC 9068). */
    case AtJWT = 'at+JWT';
}
