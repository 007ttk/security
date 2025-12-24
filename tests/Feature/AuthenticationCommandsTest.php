<?php

namespace Tests\Feature;

use ArtisanPackUI\Security\Models\AccountLockout;
use ArtisanPackUI\Security\Models\SsoConfiguration;
use ArtisanPackUI\Security\Models\SuspiciousActivity;
use ArtisanPackUI\Security\Models\UserDevice;
use ArtisanPackUI\Security\Models\UserSession;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

class AuthenticationCommandsTest extends TestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();
        $this->loadMigrationsFrom(__DIR__.'/../../database/migrations');
        $this->loadMigrationsFrom(__DIR__.'/../../database/migrations/authentication');
    }

    protected function getEnvironmentSetUp($app): void
    {
        $app['config']->set('app.key', 'base64:'.base64_encode(random_bytes(32)));
        $app['config']->set('database.default', 'testing');
        $app['config']->set('database.connections.testing', [
            'driver' => 'sqlite',
            'database' => ':memory:',
            'prefix' => '',
        ]);

        // Create the users table that the package migrations depend on
        $app['db']->connection()->getSchemaBuilder()->create('users', function ($table) {
            $table->id();
            $table->string('name');
            $table->string('email')->unique();
            $table->timestamp('email_verified_at')->nullable();
            $table->string('password');
            $table->rememberToken();
            $table->timestamps();
        });
    }

    /** @test */
    public function cleanup_expired_sessions_command_runs(): void
    {
        // Create some test sessions
        UserSession::create([
            'user_id' => 1,
            'session_token' => 'expired-token',
            'ip_address' => '192.168.1.1',
            'expires_at' => now()->subDay(),
        ]);

        UserSession::create([
            'user_id' => 1,
            'session_token' => 'active-token',
            'ip_address' => '192.168.1.1',
            'expires_at' => now()->addDay(),
        ]);

        $this->artisan('security:sessions:cleanup --dry-run')
            ->assertSuccessful();
    }

    /** @test */
    public function cleanup_inactive_devices_command_runs(): void
    {
        UserDevice::create([
            'user_id' => 1,
            'fingerprint_hash' => 'old-device',
            'device_type' => 'desktop',
            'ip_address' => '192.168.1.1',
            'last_active_at' => now()->subYear(),
        ]);

        $this->artisan('security:devices:cleanup --dry-run')
            ->assertSuccessful();
    }

    /** @test */
    public function prune_suspicious_activity_command_runs(): void
    {
        SuspiciousActivity::create([
            'type' => 'brute_force',
            'severity' => 'high',
            'risk_score' => 75,
            'ip_address' => '192.168.1.1',
            'created_at' => now()->subMonths(6),
        ]);

        $this->artisan('security:suspicious-activity:prune --dry-run')
            ->assertSuccessful();
    }

    /** @test */
    public function manage_lockout_list_command_runs(): void
    {
        AccountLockout::create([
            'user_id' => 1,
            'lockout_type' => 'temporary',
            'reason' => 'Test lockout',
            'expires_at' => now()->addMinutes(15),
            'is_active' => true,
        ]);

        $this->artisan('security:lockout list')
            ->assertSuccessful();
    }

    /** @test */
    public function manage_sso_list_command_runs(): void
    {
        SsoConfiguration::create([
            'name' => 'Test SSO',
            'slug' => 'test-sso',
            'protocol' => 'saml',
            'settings' => ['entity_id' => 'https://example.com'],
            'is_active' => true,
        ]);

        $this->artisan('security:sso list')
            ->assertSuccessful();
    }

    /** @test */
    public function security_auth_audit_command_runs(): void
    {
        $this->artisan('security:auth:audit')
            ->assertSuccessful();
    }
}
