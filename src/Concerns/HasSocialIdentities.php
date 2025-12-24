<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Concerns;

use ArtisanPackUI\Security\Models\SocialIdentity;
use Illuminate\Database\Eloquent\Relations\HasMany;

trait HasSocialIdentities
{
    /**
     * Get all social identities for the user.
     *
     * @return HasMany<SocialIdentity>
     */
    public function socialIdentities(): HasMany
    {
        return $this->hasMany(SocialIdentity::class);
    }

    /**
     * Get a specific social identity by provider.
     */
    public function getSocialIdentity(string $provider): ?SocialIdentity
    {
        return $this->socialIdentities()
            ->where('provider', $provider)
            ->first();
    }

    /**
     * Check if user has a linked social identity for a provider.
     */
    public function hasSocialIdentity(string $provider): bool
    {
        return $this->socialIdentities()
            ->where('provider', $provider)
            ->exists();
    }

    /**
     * Link a social identity to the user.
     *
     * @param  array<string, mixed>  $data
     */
    public function linkSocialIdentity(string $provider, string $providerUserId, array $data = []): SocialIdentity
    {
        return $this->socialIdentities()->updateOrCreate(
            [
                'provider' => $provider,
                'provider_user_id' => $providerUserId,
            ],
            array_merge($data, [
                'provider' => $provider,
                'provider_user_id' => $providerUserId,
            ])
        );
    }

    /**
     * Unlink a social identity from the user.
     */
    public function unlinkSocialIdentity(string $provider): bool
    {
        $identity = $this->getSocialIdentity($provider);

        if ($identity) {
            return (bool) $identity->delete();
        }

        return false;
    }

    /**
     * Get all linked providers for the user.
     *
     * @return array<string>
     */
    public function getLinkedProviders(): array
    {
        return $this->socialIdentities()
            ->pluck('provider')
            ->toArray();
    }

    /**
     * Check if this is the only authentication method for the user.
     */
    public function isSocialOnlyAuth(): bool
    {
        // User has no password set
        return empty($this->password);
    }

    /**
     * Get the primary social identity (first linked or most recently used).
     */
    public function getPrimarySocialIdentity(): ?SocialIdentity
    {
        return $this->socialIdentities()
            ->orderByDesc('updated_at')
            ->first();
    }
}
