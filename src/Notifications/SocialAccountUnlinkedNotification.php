<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Notifications;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;

class SocialAccountUnlinkedNotification extends Notification implements ShouldQueue
{
    use Queueable;

    /**
     * Create a new notification instance.
     */
    public function __construct(
        protected string $provider
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
        $providerName = ucfirst($this->provider);

        return (new MailMessage)
            ->subject("{$providerName} Account Unlinked - {$appName}")
            ->greeting('Social Account Unlinked')
            ->line("Your {$providerName} account has been unlinked from your {$appName} account.")
            ->line("**Provider:** {$providerName}")
            ->line("**Time:** ".now()->format('F j, Y \a\t g:i A T'))
            ->line("You can no longer sign in using your {$providerName} account.")
            ->action('Manage Connected Accounts', url('/settings/security/social'))
            ->line('If you did not unlink this account, please secure your account immediately.');
    }

    /**
     * Get the array representation of the notification.
     *
     * @return array<string, mixed>
     */
    public function toArray(object $notifiable): array
    {
        return [
            'type' => 'social_account_unlinked',
            'provider' => $this->provider,
            'timestamp' => now()->toIso8601String(),
        ];
    }
}
