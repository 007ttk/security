<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Concerns;

use ArtisanPackUI\Security\Models\UserDevice;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Support\Collection;

trait HasDevices
{
    /**
     * Get all devices for the user.
     *
     * @return HasMany<UserDevice>
     */
    public function devices(): HasMany
    {
        return $this->hasMany(UserDevice::class);
    }

    /**
     * Get a device by fingerprint hash.
     */
    public function getDevice(string $fingerprintHash): ?UserDevice
    {
        return $this->devices()
            ->where('fingerprint_hash', $fingerprintHash)
            ->first();
    }

    /**
     * Check if a device is recognized.
     */
    public function hasDevice(string $fingerprintHash): bool
    {
        return $this->devices()
            ->where('fingerprint_hash', $fingerprintHash)
            ->exists();
    }

    /**
     * Check if a device is trusted.
     */
    public function hasDeviceTrust(string $fingerprintHash): bool
    {
        $device = $this->getDevice($fingerprintHash);

        return $device?->isTrusted() ?? false;
    }

    /**
     * Get all trusted devices.
     *
     * @return Collection<int, UserDevice>
     */
    public function getTrustedDevices(): Collection
    {
        return $this->devices()
            ->trusted()
            ->get();
    }

    /**
     * Get the count of trusted devices.
     */
    public function getTrustedDeviceCount(): int
    {
        return $this->devices()
            ->trusted()
            ->count();
    }

    /**
     * Get all devices sorted by last use.
     *
     * @return Collection<int, UserDevice>
     */
    public function getDevicesByLastUse(): Collection
    {
        return $this->devices()
            ->orderByDesc('last_used_at')
            ->get();
    }

    /**
     * Get recently used devices.
     *
     * @return Collection<int, UserDevice>
     */
    public function getRecentDevices(int $days = 30): Collection
    {
        return $this->devices()
            ->recentlyUsed($days)
            ->orderByDesc('last_used_at')
            ->get();
    }

    /**
     * Revoke trust from all devices.
     */
    public function revokeAllDeviceTrust(): int
    {
        return $this->devices()
            ->where('is_trusted', true)
            ->update([
                'is_trusted' => false,
                'trusted_at' => null,
                'trust_expires_at' => null,
            ]);
    }

    /**
     * Remove a device.
     */
    public function removeDevice(int $deviceId): bool
    {
        return (bool) $this->devices()
            ->where('id', $deviceId)
            ->delete();
    }

    /**
     * Remove all devices except the current one.
     */
    public function removeOtherDevices(string $currentFingerprintHash): int
    {
        return $this->devices()
            ->where('fingerprint_hash', '!=', $currentFingerprintHash)
            ->delete();
    }

    /**
     * Check if the user has reached the device limit.
     */
    public function hasReachedDeviceLimit(): bool
    {
        $maxDevices = config('security.device_fingerprinting.max_devices_per_user', 10);

        return $this->devices()->count() >= $maxDevices;
    }

    /**
     * Get the current device for a fingerprint.
     */
    public function getCurrentDevice(string $fingerprintHash): ?UserDevice
    {
        return $this->getDevice($fingerprintHash);
    }
}
