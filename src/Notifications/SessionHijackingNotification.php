<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Notifications;

use ArtisanPackUI\Security\Models\UserSession;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;

class SessionHijackingNotification extends Notification implements ShouldQueue
{
    use Queueable;

    /**
     * Create a new notification instance.
     *
     * @param  array<string>  $violations
     */
    public function __construct(
        protected UserSession $session,
        protected array $violations,
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
        $violationsList = implode(', ', $this->violations);

        return (new MailMessage)
            ->subject("Security Alert: Session Compromise Attempt - {$appName}")
            ->greeting('Critical Security Alert')
            ->line("We detected a potential attempt to compromise your session on {$appName}.")
            ->line('**Violations Detected:**')
            ->line($violationsList)
            ->line("**IP Address:** {$this->ipAddress}")
            ->line("**Time:** ".now()->format('F j, Y \a\t g:i A T'))
            ->line('Your session has been terminated as a security precaution.')
            ->line('**Recommended Actions:**')
            ->line('1. Change your password immediately')
            ->line('2. Review all active sessions')
            ->line('3. Enable two-factor authentication')
            ->line('4. Check for unauthorized account changes')
            ->action('Secure Your Account', url('/settings/security'))
            ->line('If you believe this was a false alarm (e.g., you changed networks), you can safely log back in.');
    }

    /**
     * Get the array representation of the notification.
     *
     * @return array<string, mixed>
     */
    public function toArray(object $notifiable): array
    {
        return [
            'type' => 'session_hijacking_attempt',
            'session_id' => $this->session->id,
            'violations' => $this->violations,
            'ip_address' => $this->ipAddress,
            'timestamp' => now()->toIso8601String(),
        ];
    }
}
