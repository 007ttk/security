<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Listeners;

use ArtisanPackUI\Security\Events\AccountLocked;
use ArtisanPackUI\Security\Events\AccountUnlocked;
use ArtisanPackUI\Security\Events\BiometricAuthenticated;
use ArtisanPackUI\Security\Events\BiometricRegistered;
use ArtisanPackUI\Security\Events\DeviceRevoked;
use ArtisanPackUI\Security\Events\DeviceTrusted;
use ArtisanPackUI\Security\Events\NewDeviceDetected;
use ArtisanPackUI\Security\Events\SessionHijackingAttempted;
use ArtisanPackUI\Security\Events\SessionTerminated;
use ArtisanPackUI\Security\Events\SocialAccountLinked;
use ArtisanPackUI\Security\Events\SocialAccountUnlinked;
use ArtisanPackUI\Security\Events\SocialLoginSucceeded;
use ArtisanPackUI\Security\Events\SsoLoginSucceeded;
use ArtisanPackUI\Security\Events\SuspiciousActivityDetected;
use ArtisanPackUI\Security\Events\WebAuthnAuthenticated;
use ArtisanPackUI\Security\Events\WebAuthnCredentialDeleted;
use ArtisanPackUI\Security\Events\WebAuthnRegistered;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Events\Dispatcher;
use Illuminate\Support\Facades\Log;

class LogAdvancedAuthEvents implements ShouldQueue
{
    /**
     * The log channel to use.
     */
    protected string $channel;

    /**
     * Create the event listener.
     */
    public function __construct()
    {
        $this->channel = config('security.logging.channel', 'security');
    }

    /**
     * Register the listeners for the subscriber.
     */
    public function subscribe(Dispatcher $events): void
    {
        $events->listen(SocialLoginSucceeded::class, [self::class, 'handleSocialLogin']);
        $events->listen(SocialAccountLinked::class, [self::class, 'handleSocialAccountLinked']);
        $events->listen(SocialAccountUnlinked::class, [self::class, 'handleSocialAccountUnlinked']);
        $events->listen(SsoLoginSucceeded::class, [self::class, 'handleSsoLogin']);
        $events->listen(WebAuthnRegistered::class, [self::class, 'handleWebAuthnRegistered']);
        $events->listen(WebAuthnAuthenticated::class, [self::class, 'handleWebAuthnAuthenticated']);
        $events->listen(WebAuthnCredentialDeleted::class, [self::class, 'handleWebAuthnCredentialDeleted']);
        $events->listen(DeviceTrusted::class, [self::class, 'handleDeviceTrusted']);
        $events->listen(DeviceRevoked::class, [self::class, 'handleDeviceRevoked']);
        $events->listen(NewDeviceDetected::class, [self::class, 'handleNewDeviceDetected']);
        $events->listen(SuspiciousActivityDetected::class, [self::class, 'handleSuspiciousActivity']);
        $events->listen(SessionHijackingAttempted::class, [self::class, 'handleSessionHijacking']);
        $events->listen(SessionTerminated::class, [self::class, 'handleSessionTerminated']);
        $events->listen(AccountLocked::class, [self::class, 'handleAccountLocked']);
        $events->listen(AccountUnlocked::class, [self::class, 'handleAccountUnlocked']);
        $events->listen(BiometricRegistered::class, [self::class, 'handleBiometricRegistered']);
        $events->listen(BiometricAuthenticated::class, [self::class, 'handleBiometricAuthenticated']);
    }

    /**
     * Handle social login events.
     */
    public function handleSocialLogin(SocialLoginSucceeded $event): void
    {
        $this->log('info', 'social_login_succeeded', [
            'user_id' => $event->user->id ?? null,
            'provider' => $event->provider,
            'provider_id' => $event->socialUser->getId(),
            'is_new_user' => $event->isNewUser,
        ]);
    }

    /**
     * Handle social account linked events.
     */
    public function handleSocialAccountLinked(SocialAccountLinked $event): void
    {
        $this->log('info', 'social_account_linked', [
            'user_id' => $event->user->id ?? null,
            'provider' => $event->provider,
            'provider_id' => $event->socialUser->getId(),
        ]);
    }

    /**
     * Handle social account unlinked events.
     */
    public function handleSocialAccountUnlinked(SocialAccountUnlinked $event): void
    {
        $this->log('info', 'social_account_unlinked', [
            'user_id' => $event->user->id ?? null,
            'provider' => $event->provider,
            'provider_id' => $event->providerId,
        ]);
    }

    /**
     * Handle SSO login events.
     */
    public function handleSsoLogin(SsoLoginSucceeded $event): void
    {
        $this->log('info', 'sso_login_succeeded', [
            'user_id' => $event->user->id ?? null,
            'idp' => $event->configuration->name,
            'protocol' => $event->configuration->protocol,
            'is_new_user' => $event->isNewUser,
        ]);
    }

    /**
     * Handle WebAuthn registered events.
     */
    public function handleWebAuthnRegistered(WebAuthnRegistered $event): void
    {
        $this->log('info', 'webauthn_credential_registered', [
            'user_id' => $event->user->id ?? null,
            'credential_id' => $event->credential->id,
            'credential_name' => $event->credential->name,
            'ip_address' => $event->request->ip(),
        ]);
    }

    /**
     * Handle WebAuthn authenticated events.
     */
    public function handleWebAuthnAuthenticated(WebAuthnAuthenticated $event): void
    {
        $this->log('info', 'webauthn_authenticated', [
            'user_id' => $event->user->id ?? null,
            'credential_id' => $event->credential->id,
            'ip_address' => $event->request->ip(),
        ]);
    }

    /**
     * Handle WebAuthn credential deleted events.
     */
    public function handleWebAuthnCredentialDeleted(WebAuthnCredentialDeleted $event): void
    {
        $this->log('info', 'webauthn_credential_deleted', [
            'user_id' => $event->user->id ?? null,
            'credential_id' => $event->credentialId,
            'credential_name' => $event->credentialName,
        ]);
    }

    /**
     * Handle device trusted events.
     */
    public function handleDeviceTrusted(DeviceTrusted $event): void
    {
        $this->log('info', 'device_trusted', [
            'user_id' => $event->user->id ?? null,
            'device_id' => $event->device->id,
            'device_fingerprint' => $event->device->fingerprint_hash,
            'ip_address' => $event->request->ip(),
        ]);
    }

    /**
     * Handle device revoked events.
     */
    public function handleDeviceRevoked(DeviceRevoked $event): void
    {
        $this->log('info', 'device_revoked', [
            'user_id' => $event->user->id ?? null,
            'device_id' => $event->device->id,
            'reason' => $event->reason,
        ]);
    }

    /**
     * Handle new device detected events.
     */
    public function handleNewDeviceDetected(NewDeviceDetected $event): void
    {
        $this->log('notice', 'new_device_detected', [
            'user_id' => $event->user->id ?? null,
            'device_id' => $event->device->id,
            'device_fingerprint' => $event->device->fingerprint_hash,
            'ip_address' => $event->request->ip(),
            'user_agent' => $event->request->userAgent(),
        ]);
    }

    /**
     * Handle suspicious activity detected events.
     */
    public function handleSuspiciousActivity(SuspiciousActivityDetected $event): void
    {
        $level = $event->isHighSeverity() ? 'warning' : 'notice';

        $this->log($level, 'suspicious_activity_detected', [
            'user_id' => $event->user->id ?? null,
            'activity_id' => $event->activity->id,
            'type' => $event->activity->type,
            'severity' => $event->getSeverity(),
            'risk_score' => $event->getRiskScore(),
            'ip_address' => $event->request->ip(),
            'details' => $event->activity->details,
        ]);
    }

    /**
     * Handle session hijacking attempted events.
     */
    public function handleSessionHijacking(SessionHijackingAttempted $event): void
    {
        $this->log('warning', 'session_hijacking_attempted', [
            'user_id' => $event->user->id ?? null,
            'session_id' => $event->session->id,
            'violations' => $event->violations,
            'ip_address' => $event->request->ip(),
            'user_agent' => $event->request->userAgent(),
        ]);
    }

    /**
     * Handle session terminated events.
     */
    public function handleSessionTerminated(SessionTerminated $event): void
    {
        $this->log('info', 'session_terminated', [
            'user_id' => $event->user->id ?? null,
            'session_id' => $event->session->id,
            'reason' => $event->reason,
            'terminated_by_user' => $event->terminatedByUser,
        ]);
    }

    /**
     * Handle account locked events.
     */
    public function handleAccountLocked(AccountLocked $event): void
    {
        $level = $event->isPermanent() ? 'warning' : 'notice';

        $this->log($level, 'account_locked', [
            'user_id' => $event->user->id ?? null,
            'ip_address' => $event->ipAddress,
            'lockout_id' => $event->lockout->id,
            'lockout_type' => $event->getLockoutType(),
            'reason' => $event->getReason(),
        ]);
    }

    /**
     * Handle account unlocked events.
     */
    public function handleAccountUnlocked(AccountUnlocked $event): void
    {
        $this->log('info', 'account_unlocked', [
            'user_id' => $event->user->id ?? null,
            'lockout_id' => $event->lockout->id,
            'unlocked_by' => $event->unlockedBy,
        ]);
    }

    /**
     * Handle biometric registered events.
     */
    public function handleBiometricRegistered(BiometricRegistered $event): void
    {
        $this->log('info', 'biometric_registered', [
            'user_id' => $event->user->id ?? null,
            'credential_id' => $event->credential->id,
            'biometric_type' => $event->biometricType,
            'ip_address' => $event->request->ip(),
        ]);
    }

    /**
     * Handle biometric authenticated events.
     */
    public function handleBiometricAuthenticated(BiometricAuthenticated $event): void
    {
        $this->log('info', 'biometric_authenticated', [
            'user_id' => $event->user->id ?? null,
            'credential_id' => $event->credential->id,
            'biometric_type' => $event->biometricType,
            'ip_address' => $event->request->ip(),
        ]);
    }

    /**
     * Log an event.
     *
     * @param  array<string, mixed>  $context
     */
    protected function log(string $level, string $event, array $context = []): void
    {
        Log::channel($this->channel)->log($level, "[Security] {$event}", array_merge($context, [
            'timestamp' => now()->toIso8601String(),
        ]));
    }
}
