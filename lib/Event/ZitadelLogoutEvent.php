<?php

declare(strict_types=1);

namespace Zitadel\Sdk\Event;

/**
 * Fired when a user initiates logout via the SDK's logout endpoint.
 *
 * Dispatched by the bridge middleware/filter/plugin immediately before the browser
 * is redirected to Zitadel's end-session endpoint. No claims are available at this
 * point — the auth cookie has already been cleared.
 *
 * Listen to this event to write audit log entries or clean up user-specific state:
 *
 * - **CI4** — `Events::on('zitadel_logout', function (ZitadelLogoutEvent $e) { ... })`
 * - **Laravel** — `Event::listen(ZitadelLogoutEvent::class, YourListener::class)`
 * - **Symfony** — tag your listener for `Zitadel\Sdk\Event\ZitadelLogoutEvent`
 * - **Phalcon MVC** — `$eventsManager->attach('zitadel:afterLogout', $listener)`
 * - **Phalcon Micro** — `$eventsManager->attach('zitadel:afterLogout', $listener)`
 * - **Yii** — register a PSR-14 listener for `ZitadelLogoutEvent`
 */
readonly class ZitadelLogoutEvent
{
}
