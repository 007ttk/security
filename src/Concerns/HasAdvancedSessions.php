<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Concerns;

use ArtisanPackUI\Security\Models\UserSession;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Support\Collection;

trait HasAdvancedSessions
{
    /**
     * Get all sessions for the user.
     *
     * @return HasMany<UserSession>
     */
    public function advancedSessions(): HasMany
    {
        return $this->hasMany(UserSession::class);
    }

    /**
     * Get all active sessions for the user.
     *
     * @return Collection<int, UserSession>
     */
    public function getActiveSessions(): Collection
    {
        return $this->advancedSessions()
            ->active()
            ->latestActivity()
            ->get();
    }

    /**
     * Get the count of active sessions.
     */
    public function getActiveSessionCount(): int
    {
        return $this->advancedSessions()
            ->active()
            ->count();
    }

    /**
     * Check if the user has reached the session limit.
     */
    public function hasReachedSessionLimit(): bool
    {
        $maxSessions = config('security.advanced_sessions.concurrent_sessions.max_sessions', 5);

        return $this->getActiveSessionCount() >= $maxSessions;
    }

    /**
     * Get a session by ID.
     */
    public function getSession(string $sessionId): ?UserSession
    {
        return $this->advancedSessions()
            ->where('id', $sessionId)
            ->first();
    }

    /**
     * Terminate a specific session.
     */
    public function terminateSession(string $sessionId): bool
    {
        $session = $this->getSession($sessionId);

        if ($session) {
            return (bool) $session->delete();
        }

        return false;
    }

    /**
     * Terminate all sessions except the current one.
     */
    public function terminateOtherSessions(string $currentSessionId): int
    {
        return $this->advancedSessions()
            ->where('id', '!=', $currentSessionId)
            ->delete();
    }

    /**
     * Terminate all sessions.
     */
    public function terminateAllSessions(): int
    {
        return $this->advancedSessions()->delete();
    }

    /**
     * Get the current session.
     */
    public function getCurrentSession(): ?UserSession
    {
        return $this->advancedSessions()
            ->where('is_current', true)
            ->first();
    }

    /**
     * Get sessions by device.
     *
     * @return Collection<int, UserSession>
     */
    public function getSessionsByDevice(int $deviceId): Collection
    {
        return $this->advancedSessions()
            ->where('device_id', $deviceId)
            ->active()
            ->get();
    }

    /**
     * Get sessions by authentication method.
     *
     * @return Collection<int, UserSession>
     */
    public function getSessionsByAuthMethod(string $authMethod): Collection
    {
        return $this->advancedSessions()
            ->where('auth_method', $authMethod)
            ->active()
            ->get();
    }

    /**
     * Get the oldest active session (for enforcement of limits).
     */
    public function getOldestActiveSession(): ?UserSession
    {
        return $this->advancedSessions()
            ->active()
            ->orderBy('created_at')
            ->first();
    }

    /**
     * Get the most recent session before the current one.
     */
    public function getPreviousSession(string $currentSessionId): ?UserSession
    {
        return $this->advancedSessions()
            ->where('id', '!=', $currentSessionId)
            ->orderByDesc('created_at')
            ->first();
    }

    /**
     * Get session activity summary.
     *
     * @return array{total: int, active: int, by_auth_method: array<string, int>, by_device_type: array<string, int>}
     */
    public function getSessionSummary(): array
    {
        $sessions = $this->advancedSessions()->active()->get();

        $byAuthMethod = $sessions->groupBy('auth_method')
            ->map(fn ($group) => $group->count())
            ->toArray();

        $byDeviceType = $sessions->load('device')
            ->groupBy(fn ($session) => $session->device?->type ?? 'unknown')
            ->map(fn ($group) => $group->count())
            ->toArray();

        return [
            'total' => $this->advancedSessions()->count(),
            'active' => $sessions->count(),
            'by_auth_method' => $byAuthMethod,
            'by_device_type' => $byDeviceType,
        ];
    }
}
