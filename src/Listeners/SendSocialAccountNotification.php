<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Listeners;

use ArtisanPackUI\Security\Events\SocialAccountLinked;
use ArtisanPackUI\Security\Events\SocialAccountUnlinked;
use ArtisanPackUI\Security\Notifications\SocialAccountLinkedNotification;
use ArtisanPackUI\Security\Notifications\SocialAccountUnlinkedNotification;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Events\Dispatcher;

class SendSocialAccountNotification implements ShouldQueue
{
    /**
     * Register the listeners for the subscriber.
     */
    public function subscribe(Dispatcher $events): void
    {
        $events->listen(SocialAccountLinked::class, [self::class, 'handleLinked']);
        $events->listen(SocialAccountUnlinked::class, [self::class, 'handleUnlinked']);
    }

    /**
     * Handle social account linked.
     */
    public function handleLinked(SocialAccountLinked $event): void
    {
        if (! config('security.notifications.social_account', true)) {
            return;
        }

        $notificationClass = config(
            'security.notifications.classes.social_linked',
            SocialAccountLinkedNotification::class
        );

        $event->user->notify(new $notificationClass(
            $event->provider,
            $event->socialUser->getEmail()
        ));
    }

    /**
     * Handle social account unlinked.
     */
    public function handleUnlinked(SocialAccountUnlinked $event): void
    {
        if (! config('security.notifications.social_account', true)) {
            return;
        }

        $notificationClass = config(
            'security.notifications.classes.social_unlinked',
            SocialAccountUnlinkedNotification::class
        );

        $event->user->notify(new $notificationClass($event->provider));
    }
}
