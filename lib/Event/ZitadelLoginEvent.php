<?php

declare(strict_types=1);

namespace Zitadel\Sdk\Event;

use Zitadel\Sdk\Auth\Claims;

/**
 * Fired after a user successfully completes the PKCE login flow.
 *
 * Dispatched by the bridge middleware/filter/plugin immediately after the access
 * token is validated and before the browser is redirected to the post-login URL.
 *
 * Listen to this event to sync the user record, update last-seen timestamps, or
 * write audit log entries. The event is framework-specific in how it is dispatched
 * but the event class itself is framework-agnostic:
 *
 * - **CI4** — `Events::on('zitadel_login', function (ZitadelLoginEvent $e) { ... })`
 * - **Laravel** — `Event::listen(ZitadelLoginEvent::class, YourListener::class)`
 * - **Symfony** — tag your listener for `Zitadel\Sdk\Event\ZitadelLoginEvent`
 * - **Phalcon MVC** — `$eventsManager->attach('zitadel:afterLogin', $listener)`
 * - **Phalcon Micro** — `$eventsManager->attach('zitadel:afterLogin', $listener)`
 * - **Yii** — register a PSR-14 listener for `ZitadelLoginEvent`
 */
readonly class ZitadelLoginEvent
{
    public function __construct(public readonly Claims $claims)
    {
    }
}
