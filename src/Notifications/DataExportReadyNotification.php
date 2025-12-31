<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Notifications;

use ArtisanPackUI\Security\Models\PortabilityRequest;
use Illuminate\Bus\Queueable;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;

class DataExportReadyNotification extends Notification
{
    use Queueable;

    public function __construct(public PortabilityRequest $request) {}

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
        $expiryHours = config('security-compliance.compliance.portability.download_expiry_hours', 72);

        return (new MailMessage)
            ->subject('Your Data Export is Ready')
            ->greeting('Hello!')
            ->line('Your data export request has been processed and is ready for download.')
            ->line("Request Number: {$this->request->request_number}")
            ->line("Format: {$this->request->format}")
            ->line("Download Limit: {$this->request->download_limit} times")
            ->line("Expires: {$expiryHours} hours from now")
            ->action('Download Your Data', url('/compliance/exports/'.$this->request->request_number.'/download'))
            ->line('Please download your data before the link expires.');
    }

    /**
     * Get the array representation of the notification.
     *
     * @return array<string, mixed>
     */
    public function toArray(object $notifiable): array
    {
        return [
            'request_number' => $this->request->request_number,
            'status' => $this->request->status,
            'format' => $this->request->format,
            'expires_at' => $this->request->expires_at?->toIso8601String(),
        ];
    }
}
