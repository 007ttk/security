<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Concerns;

use ArtisanPackUI\Security\Models\SsoIdentity;
use Illuminate\Database\Eloquent\Relations\HasMany;

trait HasSsoIdentities
{
    /**
     * Get all SSO identities for the user.
     *
     * @return HasMany<SsoIdentity>
     */
    public function ssoIdentities(): HasMany
    {
        return $this->hasMany(SsoIdentity::class);
    }

    /**
     * Get a specific SSO identity by IdP.
     */
    public function getSsoIdentity(string $idpId): ?SsoIdentity
    {
        return $this->ssoIdentities()
            ->where('idp_id', $idpId)
            ->first();
    }

    /**
     * Check if user has a linked SSO identity for an IdP.
     */
    public function hasSsoIdentity(string $idpId): bool
    {
        return $this->ssoIdentities()
            ->where('idp_id', $idpId)
            ->exists();
    }

    /**
     * Link an SSO identity to the user.
     *
     * @param  array<string, mixed>  $attributes
     */
    public function linkSsoIdentity(
        string $idpId,
        string $idpUserId,
        ?string $nameId = null,
        array $attributes = [],
        ?string $sessionIndex = null
    ): SsoIdentity {
        return $this->ssoIdentities()->updateOrCreate(
            [
                'idp_id' => $idpId,
                'idp_user_id' => $idpUserId,
            ],
            [
                'name_id' => $nameId,
                'attributes' => $attributes,
                'session_index' => $sessionIndex,
                'last_authenticated_at' => now(),
            ]
        );
    }

    /**
     * Unlink an SSO identity from the user.
     */
    public function unlinkSsoIdentity(string $idpId): bool
    {
        $identity = $this->getSsoIdentity($idpId);

        if ($identity) {
            return (bool) $identity->delete();
        }

        return false;
    }

    /**
     * Get all linked IdPs for the user.
     *
     * @return array<string>
     */
    public function getLinkedIdps(): array
    {
        return $this->ssoIdentities()
            ->pluck('idp_id')
            ->toArray();
    }

    /**
     * Check if this user was provisioned via SSO (JIT provisioning).
     */
    public function isJitProvisioned(): bool
    {
        // User has SSO identity and no password
        return $this->ssoIdentities()->exists() && empty($this->password);
    }

    /**
     * Get the primary SSO identity (most recently authenticated).
     */
    public function getPrimarySsoIdentity(): ?SsoIdentity
    {
        return $this->ssoIdentities()
            ->orderByDesc('last_authenticated_at')
            ->first();
    }

    /**
     * Get the session index for single logout.
     */
    public function getSsoSessionIndex(string $idpId): ?string
    {
        $identity = $this->getSsoIdentity($idpId);

        return $identity?->session_index;
    }
}
