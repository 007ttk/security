<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Notifications;

use ArtisanPackUI\Security\Models\ErasureRequest;
use Illuminate\Bus\Queueable;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;

class ErasureRequestCompletedNotification extends Notification
{
    use Queueable;

    public function __construct(public ErasureRequest $request) {}

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
        return (new MailMessage)
            ->subject('Your Data Erasure Request Has Been Completed')
            ->greeting('Hello!')
            ->line('We have completed processing your data erasure request.')
            ->line("Request Number: {$this->request->request_number}")
            ->line("Completed At: {$this->request->completed_at?->format('F j, Y g:i A')}")
            ->line('Your personal data has been removed from our systems in accordance with your request.')
            ->line('If you have any questions, please contact our support team.');
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
            'completed_at' => $this->request->completed_at?->toIso8601String(),
        ];
    }
}
