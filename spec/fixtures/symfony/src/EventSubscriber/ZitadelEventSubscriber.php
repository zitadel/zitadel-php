<?php

declare(strict_types=1);

namespace App\EventSubscriber;

use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Zitadel\Sdk\Event\ZitadelLoginEvent;
use Zitadel\Sdk\Event\ZitadelLogoutEvent;

/**
 * Writes a stderr marker for each Zitadel event so the integration spec can
 * assert dispatch without any file or HTTP endpoint coupling.
 */
final class ZitadelEventSubscriber implements EventSubscriberInterface
{
    public static function getSubscribedEvents(): array
    {
        return [
            ZitadelLoginEvent::class  => 'onLogin',
            ZitadelLogoutEvent::class => 'onLogout',
        ];
    }

    public function onLogin(ZitadelLoginEvent $event): void
    {
        error_log('[ZITADEL_EVENT] ZitadelLoginEvent');
    }

    public function onLogout(ZitadelLogoutEvent $event): void
    {
        error_log('[ZITADEL_EVENT] ZitadelLogoutEvent');
    }
}
