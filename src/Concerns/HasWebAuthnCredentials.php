<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Concerns;

use ArtisanPackUI\Security\Models\WebAuthnCredential;
use Illuminate\Database\Eloquent\Relations\HasMany;

trait HasWebAuthnCredentials
{
    /**
     * Get all WebAuthn credentials for the user.
     *
     * @return HasMany<WebAuthnCredential>
     */
    public function webAuthnCredentials(): HasMany
    {
        return $this->hasMany(WebAuthnCredential::class);
    }

    /**
     * Check if the user has any WebAuthn credentials.
     */
    public function hasWebAuthnCredentials(): bool
    {
        return $this->webAuthnCredentials()->exists();
    }

    /**
     * Get the count of WebAuthn credentials.
     */
    public function getWebAuthnCredentialCount(): int
    {
        return $this->webAuthnCredentials()->count();
    }

    /**
     * Check if the user can add more WebAuthn credentials.
     */
    public function canAddWebAuthnCredential(): bool
    {
        $maxCredentials = config('security.webauthn.max_credentials_per_user', 10);

        return $this->getWebAuthnCredentialCount() < $maxCredentials;
    }

    /**
     * Get all credential IDs for the user (for authentication options).
     *
     * @return array<array{id: string, type: string, transports: array<string>}>
     */
    public function getWebAuthnCredentialDescriptors(): array
    {
        return $this->webAuthnCredentials()
            ->get()
            ->map(function (WebAuthnCredential $credential) {
                return [
                    'id' => $credential->getCredentialIdBase64(),
                    'type' => 'public-key',
                    'transports' => $credential->transports ?? [],
                ];
            })
            ->toArray();
    }

    /**
     * Find a WebAuthn credential by its ID.
     */
    public function findWebAuthnCredential(string $credentialId): ?WebAuthnCredential
    {
        return WebAuthnCredential::findByCredentialIdForUser($credentialId, $this->id);
    }

    /**
     * Check if the user has passkeys (discoverable credentials).
     */
    public function hasPasskeys(): bool
    {
        return $this->webAuthnCredentials()
            ->where('backup_eligible', true)
            ->exists();
    }

    /**
     * Check if the user has platform authenticators (built-in biometric).
     */
    public function hasPlatformAuthenticators(): bool
    {
        return $this->webAuthnCredentials()
            ->get()
            ->some(fn ($credential) => $credential->isPlatformAuthenticator());
    }

    /**
     * Check if the user has security keys.
     */
    public function hasSecurityKeys(): bool
    {
        return $this->webAuthnCredentials()
            ->get()
            ->some(fn ($credential) => $credential->isRoamingAuthenticator());
    }

    /**
     * Check if passwordless authentication is enabled for the user.
     */
    public function isPasswordlessEnabled(): bool
    {
        return $this->hasWebAuthnCredentials()
            && config('security.webauthn.allow_passwordless', true);
    }

    /**
     * Remove a WebAuthn credential by ID.
     */
    public function removeWebAuthnCredential(int $credentialId): bool
    {
        return (bool) $this->webAuthnCredentials()
            ->where('id', $credentialId)
            ->delete();
    }

    /**
     * Get the most recently used WebAuthn credential.
     */
    public function getLastUsedWebAuthnCredential(): ?WebAuthnCredential
    {
        return $this->webAuthnCredentials()
            ->orderByDesc('last_used_at')
            ->first();
    }
}
