<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Notifications;

use ArtisanPackUI\Security\Models\ComplianceViolation;
use Illuminate\Bus\Queueable;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;

class ComplianceViolationNotification extends Notification
{
    use Queueable;

    public function __construct(public ComplianceViolation $violation) {}

    /**
     * Get the notification's delivery channels.
     *
     * @return array<string>
     */
    public function via(object $notifiable): array
    {
        return ['mail'];
    }

    /**
     * Get the mail representation of the notification.
     */
    public function toMail(object $notifiable): MailMessage
    {
        $severity = strtoupper($this->violation->severity);

        return (new MailMessage)
            ->subject("[{$severity}] Compliance Violation Detected")
            ->greeting('Compliance Alert')
            ->line("A new compliance violation has been detected that requires your attention.")
            ->line("**Violation Number:** {$this->violation->violation_number}")
            ->line("**Severity:** {$severity}")
            ->line("**Category:** {$this->violation->category}")
            ->line("**Title:** {$this->violation->title}")
            ->line("**Description:** {$this->violation->description}")
            ->when($this->violation->remediation_deadline, function ($message) {
                return $message->line("**Remediation Deadline:** {$this->violation->remediation_deadline->format('F j, Y')}");
            })
            ->action('View Violation Details', route('compliance.violations.show', $this->violation))
            ->line('Please address this violation promptly.');
    }

    /**
     * Get the array representation of the notification.
     *
     * @return array<string, mixed>
     */
    public function toArray(object $notifiable): array
    {
        return [
            'violation_number' => $this->violation->violation_number,
            'severity' => $this->violation->severity,
            'category' => $this->violation->category,
            'title' => $this->violation->title,
        ];
    }
}
