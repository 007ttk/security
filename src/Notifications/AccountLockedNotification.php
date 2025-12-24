<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Notifications;

use ArtisanPackUI\Security\Models\AccountLockout;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;

class AccountLockedNotification extends Notification implements ShouldQueue
{
    use Queueable;

    /**
     * Create a new notification instance.
     */
    public function __construct(
        protected AccountLockout $lockout,
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

        $mail = (new MailMessage)
            ->subject("Account Locked - {$appName}")
            ->greeting('Account Security Alert');

        if ($this->lockout->isPermanent()) {
            $mail->line("Your {$appName} account has been permanently locked due to security concerns.")
                ->line("**Reason:** {$this->lockout->reason}")
                ->line('Please contact our support team to restore access to your account.')
                ->action('Contact Support', url('/support'));
        } else {
            $remainingMinutes = ceil($this->lockout->getRemainingSeconds() / 60);
            $ipDisplay = $this->ipAddress ?? 'Unknown';

            $mail->line("Your {$appName} account has been temporarily locked.")
                ->line("**Reason:** {$this->lockout->reason}")
                ->line("**Lock Duration:** {$remainingMinutes} minutes remaining")
                ->line("**IP Address:** {$ipDisplay}")
                ->line("You can try again after the lockout period expires.");

            if ($this->lockout->isSoft()) {
                $mail->line('To unlock your account sooner, you may need to complete additional verification.')
                    ->action('Verify Identity', url('/auth/verify'));
            }
        }

        $mail->line('If you did not attempt to access your account, please secure it immediately by:')
            ->line('1. Changing your password')
            ->line('2. Enabling two-factor authentication')
            ->line('3. Reviewing recent account activity');

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
            'type' => 'account_locked',
            'lockout_id' => $this->lockout->id,
            'lockout_type' => $this->lockout->lockout_type,
            'reason' => $this->lockout->reason,
            'ip_address' => $this->ipAddress,
            'expires_at' => $this->lockout->expires_at?->toIso8601String(),
            'timestamp' => now()->toIso8601String(),
        ];
    }
}
