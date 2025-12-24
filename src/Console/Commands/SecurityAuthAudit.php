<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Console\Commands;

use ArtisanPackUI\Security\Models\AccountLockout;
use ArtisanPackUI\Security\Models\SsoConfiguration;
use ArtisanPackUI\Security\Models\SuspiciousActivity;
use ArtisanPackUI\Security\Models\UserDevice;
use ArtisanPackUI\Security\Models\UserSession;
use ArtisanPackUI\Security\Models\WebAuthnCredential;
use Illuminate\Console\Command;

class SecurityAuthAudit extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'security:auth:audit
                            {--days=30 : Audit period in days}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Generate an authentication security audit report';

    /**
     * Execute the console command.
     */
    public function handle(): int
    {
        $days = (int) $this->option('days');
        $since = now()->subDays($days);

        $this->info("Authentication Security Audit Report");
        $this->info("Period: Last {$days} days (since {$since->format('Y-m-d')})");
        $this->line(str_repeat('=', 60));

        // SSO Configuration Status
        $this->newLine();
        $this->info('SSO Configurations:');
        $ssoConfigs = SsoConfiguration::all();
        $this->line("  Total configurations: {$ssoConfigs->count()}");
        $this->line("  Active: {$ssoConfigs->where('is_active', true)->count()}");
        $this->line("  Inactive: {$ssoConfigs->where('is_active', false)->count()}");

        // WebAuthn Statistics
        $this->newLine();
        $this->info('WebAuthn/Passkeys:');
        $webauthnTotal = WebAuthnCredential::count();
        $webauthnNew = WebAuthnCredential::where('created_at', '>=', $since)->count();
        $platformAuth = WebAuthnCredential::where('is_platform_credential', true)->count();
        $this->line("  Total credentials: {$webauthnTotal}");
        $this->line("  New registrations: {$webauthnNew}");
        $this->line("  Platform authenticators (biometric): {$platformAuth}");
        $this->line("  Security keys: ".($webauthnTotal - $platformAuth));

        // Device Statistics
        $this->newLine();
        $this->info('Devices:');
        $devicesTotal = UserDevice::count();
        $devicesNew = UserDevice::where('created_at', '>=', $since)->count();
        $devicesTrusted = UserDevice::where('is_trusted', true)->count();
        $this->line("  Total devices: {$devicesTotal}");
        $this->line("  New devices: {$devicesNew}");
        $this->line("  Trusted devices: {$devicesTrusted}");

        // Session Statistics
        $this->newLine();
        $this->info('Sessions:');
        $sessionsActive = UserSession::active()->count();
        $sessionsTotal = UserSession::where('created_at', '>=', $since)->count();
        $this->line("  Currently active: {$sessionsActive}");
        $this->line("  Created in period: {$sessionsTotal}");

        // Suspicious Activity
        $this->newLine();
        $this->info('Suspicious Activity:');
        $suspiciousTotal = SuspiciousActivity::where('created_at', '>=', $since)->count();
        $suspiciousBySeverity = SuspiciousActivity::where('created_at', '>=', $since)
            ->selectRaw('severity, count(*) as count')
            ->groupBy('severity')
            ->pluck('count', 'severity');

        $this->line("  Total incidents: {$suspiciousTotal}");
        foreach ($suspiciousBySeverity as $severity => $count) {
            $this->line("  {$severity}: {$count}");
        }

        // Account Lockouts
        $this->newLine();
        $this->info('Account Lockouts:');
        $lockoutsTotal = AccountLockout::where('created_at', '>=', $since)->count();
        $lockoutsActive = AccountLockout::active()->count();
        $lockoutsByType = AccountLockout::where('created_at', '>=', $since)
            ->selectRaw('lockout_type, count(*) as count')
            ->groupBy('lockout_type')
            ->pluck('count', 'lockout_type');

        $this->line("  Total in period: {$lockoutsTotal}");
        $this->line("  Currently active: {$lockoutsActive}");
        foreach ($lockoutsByType as $type => $count) {
            $this->line("  {$type}: {$count}");
        }

        // Recommendations
        $this->newLine();
        $this->info('Recommendations:');
        $recommendations = [];

        if ($ssoConfigs->where('is_active', true)->isEmpty()) {
            $recommendations[] = 'Consider enabling SSO for enterprise authentication';
        }

        if ($platformAuth < $webauthnTotal * 0.3) {
            $recommendations[] = 'Encourage users to register biometric authenticators';
        }

        $suspiciousCritical = SuspiciousActivity::where('created_at', '>=', $since)
            ->where('severity', SuspiciousActivity::SEVERITY_CRITICAL)
            ->count();

        if ($suspiciousCritical > 0) {
            $recommendations[] = "Review {$suspiciousCritical} critical suspicious activity incidents";
        }

        if ($lockoutsActive > 10) {
            $recommendations[] = "Review {$lockoutsActive} active account lockouts";
        }

        if (empty($recommendations)) {
            $this->line('  No immediate actions required');
        } else {
            foreach ($recommendations as $i => $rec) {
                $this->line('  '.($i + 1).'. '.$rec);
            }
        }

        $this->newLine();
        $this->line(str_repeat('=', 60));
        $this->info('Audit complete.');

        return self::SUCCESS;
    }
}
