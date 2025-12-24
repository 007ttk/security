<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Listeners;

use ArtisanPackUI\Security\Authentication\Lockout\AccountLockoutManager;
use ArtisanPackUI\Security\Events\SuspiciousActivityDetected;
use ArtisanPackUI\Security\Models\SuspiciousActivity;
use ArtisanPackUI\Security\Notifications\SuspiciousLoginAttempt;
use Illuminate\Contracts\Queue\ShouldQueue;

class HandleSuspiciousActivity implements ShouldQueue
{
    /**
     * Create the event listener.
     */
    public function __construct(
        protected AccountLockoutManager $lockoutManager
    ) {}

    /**
     * Handle the event.
     */
    public function handle(SuspiciousActivityDetected $event): void
    {
        $activity = $event->activity;

        // Handle based on severity
        match ($activity->severity) {
            SuspiciousActivity::SEVERITY_CRITICAL => $this->handleCritical($event),
            SuspiciousActivity::SEVERITY_HIGH => $this->handleHigh($event),
            SuspiciousActivity::SEVERITY_MEDIUM => $this->handleMedium($event),
            default => $this->handleLow($event),
        };
    }

    /**
     * Handle critical severity events.
     */
    protected function handleCritical(SuspiciousActivityDetected $event): void
    {
        // Immediately lock out the IP
        $this->lockoutManager->lockIp(
            $event->request->ip(),
            config('security.account_lockout.lockout_duration', 60),
            'Critical suspicious activity detected',
            ['activity_id' => $event->activity->id]
        );

        // Lock the user account if applicable
        if ($event->user) {
            $this->lockoutManager->lockUser(
                $event->user,
                config('security.account_lockout.lockout_duration', 60),
                'Critical suspicious activity detected',
                ['activity_id' => $event->activity->id]
            );

            // Send notification
            $this->notifyUser($event);
        }

        // Notify administrators
        $this->notifyAdministrators($event);
    }

    /**
     * Handle high severity events.
     */
    protected function handleHigh(SuspiciousActivityDetected $event): void
    {
        // Notify the user if applicable
        if ($event->user) {
            $this->notifyUser($event);
        }

        // Notify administrators for high severity
        $this->notifyAdministrators($event);
    }

    /**
     * Handle medium severity events.
     */
    protected function handleMedium(SuspiciousActivityDetected $event): void
    {
        // Notify the user
        if ($event->user && $this->shouldNotifyUser($event)) {
            $this->notifyUser($event);
        }
    }

    /**
     * Handle low severity events.
     */
    protected function handleLow(SuspiciousActivityDetected $event): void
    {
        // Just log (already handled by LogAdvancedAuthEvents)
    }

    /**
     * Notify the user about suspicious activity.
     */
    protected function notifyUser(SuspiciousActivityDetected $event): void
    {
        if (! $event->user) {
            return;
        }

        $notificationClass = config(
            'security.notifications.suspicious_activity',
            SuspiciousLoginAttempt::class
        );

        $event->user->notify(new $notificationClass(
            $event->activity,
            $event->request->ip(),
            $event->request->userAgent()
        ));
    }

    /**
     * Notify administrators about suspicious activity.
     */
    protected function notifyAdministrators(SuspiciousActivityDetected $event): void
    {
        $adminEmails = config('security.admin_emails', []);

        if (empty($adminEmails)) {
            return;
        }

        // Get the notification class
        $notificationClass = config(
            'security.notifications.admin_suspicious_activity',
            SuspiciousLoginAttempt::class
        );

        foreach ($adminEmails as $email) {
            // Use anonymous notifiable for admin emails
            \Illuminate\Support\Facades\Notification::route('mail', $email)
                ->notify(new $notificationClass(
                    $event->activity,
                    $event->request->ip(),
                    $event->request->userAgent(),
                    $event->user
                ));
        }
    }

    /**
     * Determine if the user should be notified.
     */
    protected function shouldNotifyUser(SuspiciousActivityDetected $event): bool
    {
        // Check user preferences if available
        if (method_exists($event->user, 'wantsSecurityNotifications')) {
            return $event->user->wantsSecurityNotifications();
        }

        return config('security.notifications.enabled', true);
    }
}
