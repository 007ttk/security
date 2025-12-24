<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Listeners;

use ArtisanPackUI\Security\Events\NewDeviceDetected;
use ArtisanPackUI\Security\Notifications\NewDeviceLogin;
use Illuminate\Contracts\Queue\ShouldQueue;

class SendNewDeviceNotification implements ShouldQueue
{
    /**
     * Handle the event.
     */
    public function handle(NewDeviceDetected $event): void
    {
        if (! config('security.notifications.new_device_login', true)) {
            return;
        }

        // Check if user wants security notifications
        if (method_exists($event->user, 'wantsSecurityNotifications') && ! $event->user->wantsSecurityNotifications()) {
            return;
        }

        $notificationClass = config(
            'security.notifications.classes.new_device',
            NewDeviceLogin::class
        );

        $event->user->notify(new $notificationClass(
            $event->device,
            $event->request->ip(),
            $event->request->userAgent()
        ));
    }
}
