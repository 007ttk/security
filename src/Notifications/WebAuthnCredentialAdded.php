<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Notifications;

use ArtisanPackUI\Security\Models\WebAuthnCredential;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;

class WebAuthnCredentialAdded extends Notification implements ShouldQueue
{
    use Queueable;

    /**
     * Create a new notification instance.
     */
    public function __construct(
        protected WebAuthnCredential $credential,
        protected ?string $ipAddress = null
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
        $credentialType = $this->credential->is_platform_credential ? 'biometric' : 'security key';

        return (new MailMessage)
            ->subject("New Security Key Added - {$appName}")
            ->greeting('Security Key Added')
            ->line("A new {$credentialType} has been added to your {$appName} account.")
            ->line("**Name:** {$this->credential->name}")
            ->line("**Type:** ".ucfirst($credentialType))
            ->line("**IP Address:** ".($this->ipAddress ?? 'Unknown'))
            ->line("**Time:** ".now()->format('F j, Y \a\t g:i A T'))
            ->line('You can now use this credential to sign in to your account.')
            ->action('Manage Security Keys', url('/settings/security/webauthn'))
            ->line('If you did not add this credential, please remove it immediately and secure your account.');
    }

    /**
     * Get the array representation of the notification.
     *
     * @return array<string, mixed>
     */
    public function toArray(object $notifiable): array
    {
        return [
            'type' => 'webauthn_credential_added',
            'credential_id' => $this->credential->id,
            'credential_name' => $this->credential->name,
            'is_platform_credential' => $this->credential->is_platform_credential,
            'ip_address' => $this->ipAddress,
            'timestamp' => now()->toIso8601String(),
        ];
    }
}
