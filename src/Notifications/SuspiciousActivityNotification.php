<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Notifications;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;
use Illuminate\Support\Collection;

class SuspiciousActivityNotification extends Notification implements ShouldQueue
{
    use Queueable;

    public function __construct(
        protected Collection $suspiciousActivities
    ) {}

    /**
     * Get the notification's delivery channels.
     */
    public function via(object $notifiable): array
    {
        return config('artisanpack.security.eventLogging.alerting.channels', ['mail']);
    }

    /**
     * Get the mail representation of the notification.
     */
    public function toMail(object $notifiable): MailMessage
    {
        $message = (new MailMessage)
            ->subject('Security Alert: Suspicious Activity Detected')
            ->line('Suspicious activity has been detected on your application.')
            ->line("Total patterns detected: {$this->suspiciousActivities->count()}");

        foreach ($this->suspiciousActivities as $activity) {
            $message->line($this->formatActivity($activity));
        }

        $message->line('Please review the security dashboard for more details.');

        if ($dashboardUrl = $this->getDashboardUrl()) {
            $message->action('View Security Dashboard', $dashboardUrl);
        }

        return $message;
    }

    /**
     * Get the array representation of the notification.
     */
    public function toArray(object $notifiable): array
    {
        return [
            'type' => 'suspicious_activity',
            'count' => $this->suspiciousActivities->count(),
            'activities' => $this->suspiciousActivities->toArray(),
            'detected_at' => now()->toIso8601String(),
        ];
    }

    /**
     * Format a suspicious activity for display.
     */
    protected function formatActivity(array $activity): string
    {
        $type = $activity['type'] ?? 'unknown';
        $count = $activity['count'] ?? 0;
        $threshold = $activity['threshold'] ?? 0;
        $window = $activity['window_minutes'] ?? 0;

        return match ($type) {
            'failed_logins_per_ip' => sprintf(
                '- Failed logins from IP %s: %d attempts (threshold: %d) in %d minutes',
                $activity['ip_address'] ?? 'unknown',
                $count,
                $threshold,
                $window
            ),
            'failed_logins_per_user' => sprintf(
                '- Failed logins for user ID %s: %d attempts (threshold: %d) in %d minutes',
                $activity['user_id'] ?? 'unknown',
                $count,
                $threshold,
                $window
            ),
            'permission_denials_per_user' => sprintf(
                '- Permission denials for user ID %s: %d denials (threshold: %d) in %d minutes',
                $activity['user_id'] ?? 'unknown',
                $count,
                $threshold,
                $window
            ),
            default => sprintf(
                '- %s: %d occurrences (threshold: %d)',
                $type,
                $count,
                $threshold
            ),
        };
    }

    /**
     * Get the security dashboard URL.
     */
    protected function getDashboardUrl(): ?string
    {
        $dashboardConfig = config('artisanpack.security.eventLogging.dashboard', []);

        if (! ($dashboardConfig['enabled'] ?? false)) {
            return null;
        }

        $prefix = $dashboardConfig['routePrefix'] ?? 'security';

        return url($prefix . '/events');
    }
}
