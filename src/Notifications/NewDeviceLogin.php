<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Notifications;

use ArtisanPackUI\Security\Models\UserDevice;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;

class NewDeviceLogin extends Notification implements ShouldQueue
{
    use Queueable;

    /**
     * Create a new notification instance.
     */
    public function __construct(
        protected UserDevice $device,
        protected ?string $ipAddress = null,
        protected ?string $userAgent = null
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
        $deviceInfo = $this->getDeviceDescription();

        return (new MailMessage)
            ->subject("New Device Login - {$appName}")
            ->greeting('New Device Detected')
            ->line("We noticed a login to your {$appName} account from a new device.")
            ->line("**Device:** {$deviceInfo}")
            ->line("**IP Address:** {$this->ipAddress}")
            ->line("**Time:** ".now()->format('F j, Y \a\t g:i A T'))
            ->line('If this was you, you can ignore this email.')
            ->line('If you did not log in from this device, please secure your account immediately.')
            ->action('Review Security Settings', url('/settings/security'))
            ->line('For your protection, we recommend enabling two-factor authentication if you haven\'t already.');
    }

    /**
     * Get the array representation of the notification.
     *
     * @return array<string, mixed>
     */
    public function toArray(object $notifiable): array
    {
        return [
            'type' => 'new_device_login',
            'device_id' => $this->device->id,
            'device_name' => $this->device->device_name,
            'device_type' => $this->device->device_type,
            'ip_address' => $this->ipAddress,
            'user_agent' => $this->userAgent,
            'timestamp' => now()->toIso8601String(),
        ];
    }

    /**
     * Get a human-readable device description.
     */
    protected function getDeviceDescription(): string
    {
        $parts = [];

        if ($this->device->device_name) {
            $parts[] = $this->device->device_name;
        }

        if ($this->device->browser) {
            $browserInfo = $this->device->browser;
            if ($this->device->browser_version) {
                $browserInfo .= ' '.$this->device->browser_version;
            }
            $parts[] = $browserInfo;
        }

        if ($this->device->platform) {
            $parts[] = $this->device->platform;
        }

        return implode(' on ', array_filter($parts)) ?: 'Unknown device';
    }
}
