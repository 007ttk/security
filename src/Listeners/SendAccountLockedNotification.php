<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Listeners;

use ArtisanPackUI\Security\Events\AccountLocked;
use ArtisanPackUI\Security\Notifications\AccountLockedNotification;
use Illuminate\Contracts\Queue\ShouldQueue;

class SendAccountLockedNotification implements ShouldQueue
{
    /**
     * Handle the event.
     */
    public function handle(AccountLocked $event): void
    {
        if (! config('security.notifications.account_locked', true)) {
            return;
        }

        if (! $event->user) {
            return;
        }

        $notificationClass = config(
            'security.notifications.classes.account_locked',
            AccountLockedNotification::class
        );

        $event->user->notify(new $notificationClass(
            $event->lockout,
            $event->ipAddress
        ));
    }
}
