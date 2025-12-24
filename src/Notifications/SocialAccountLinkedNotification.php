<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Notifications;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;

class SocialAccountLinkedNotification extends Notification implements ShouldQueue
{
    use Queueable;

    /**
     * Create a new notification instance.
     */
    public function __construct(
        protected string $provider,
        protected ?string $socialEmail = null
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

        $mail = (new MailMessage)
            ->subject("{$providerName} Account Linked - {$appName}")
            ->greeting('Social Account Linked')
            ->line("Your {$providerName} account has been linked to your {$appName} account.")
            ->line("**Provider:** {$providerName}");

        if ($this->socialEmail) {
            $mail->line("**Email:** {$this->socialEmail}");
        }

        $mail->line("**Time:** ".now()->format('F j, Y \a\t g:i A T'))
            ->line("You can now sign in using your {$providerName} account.")
            ->action('Manage Connected Accounts', url('/settings/security/social'))
            ->line('If you did not link this account, please remove it immediately.');

        return $mail;
    }

    /**
     * Get the array representation of the notification.
     *
     * @return array<string, mixed>
     */
    public function toArray(object $notifiable): array
    {
        return [
            'type' => 'social_account_linked',
            'provider' => $this->provider,
            'social_email' => $this->socialEmail,
            'timestamp' => now()->toIso8601String(),
        ];
    }
}
