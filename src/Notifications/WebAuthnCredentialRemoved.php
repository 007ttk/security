<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Notifications;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;

class WebAuthnCredentialRemoved extends Notification implements ShouldQueue
{
    use Queueable;

    /**
     * Create a new notification instance.
     */
    public function __construct(
        protected string $credentialId,
        protected string $credentialName
    ) {}

    /**
     * Get the notification's delivery channels.
     *
     * @return array<int, string>
     */
    public function via(object $notifiable): array
    {
        return ['mail', 'database'];
    }

    /**
     * Get the mail representation of the notification.
     */
    public function toMail(object $notifiable): MailMessage
    {
        $appName = config('app.name');

        return (new MailMessage)
            ->subject("Security Key Removed - {$appName}")
            ->greeting('Security Key Removed')
            ->line("A security key has been removed from your {$appName} account.")
            ->line("**Name:** {$this->credentialName}")
            ->line("**Time:** ".now()->format('F j, Y \a\t g:i A T'))
            ->line('This credential can no longer be used to sign in to your account.')
            ->action('Manage Security Keys', url('/settings/security/webauthn'))
            ->line('If you did not remove this credential, please secure your account immediately.');
    }

    /**
     * Get the array representation of the notification.
     *
     * @return array<string, mixed>
     */
    public function toArray(object $notifiable): array
    {
        return [
            'type' => 'webauthn_credential_removed',
            'credential_id' => $this->credentialId,
            'credential_name' => $this->credentialName,
            'timestamp' => now()->toIso8601String(),
        ];
    }
}
