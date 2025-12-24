<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Listeners;

use ArtisanPackUI\Security\Events\WebAuthnCredentialDeleted;
use ArtisanPackUI\Security\Events\WebAuthnRegistered;
use ArtisanPackUI\Security\Notifications\WebAuthnCredentialAdded;
use ArtisanPackUI\Security\Notifications\WebAuthnCredentialRemoved;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Events\Dispatcher;

class SendWebAuthnCredentialNotification implements ShouldQueue
{
    /**
     * Register the listeners for the subscriber.
     */
    public function subscribe(Dispatcher $events): void
    {
        $events->listen(WebAuthnRegistered::class, [self::class, 'handleRegistered']);
        $events->listen(WebAuthnCredentialDeleted::class, [self::class, 'handleDeleted']);
    }

    /**
     * Handle WebAuthn credential registered.
     */
    public function handleRegistered(WebAuthnRegistered $event): void
    {
        if (! config('security.notifications.webauthn_credential', true)) {
            return;
        }

        $notificationClass = config(
            'security.notifications.classes.webauthn_added',
            WebAuthnCredentialAdded::class
        );

        $event->user->notify(new $notificationClass(
            $event->credential,
            $event->request->ip()
        ));
    }

    /**
     * Handle WebAuthn credential deleted.
     */
    public function handleDeleted(WebAuthnCredentialDeleted $event): void
    {
        if (! config('security.notifications.webauthn_credential', true)) {
            return;
        }

        $notificationClass = config(
            'security.notifications.classes.webauthn_removed',
            WebAuthnCredentialRemoved::class
        );

        $event->user->notify(new $notificationClass(
            $event->credentialId,
            $event->credentialName
        ));
    }
}
