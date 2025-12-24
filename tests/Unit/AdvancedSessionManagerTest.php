<?php

namespace Tests\Unit;

use ArtisanPackUI\Security\Authentication\Session\AdvancedSessionManager;
use ArtisanPackUI\Security\Models\UserSession;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Tests\TestCase;

class AdvancedSessionManagerTest extends TestCase
{
    use RefreshDatabase;

    protected AdvancedSessionManager $manager;

    protected function setUp(): void
    {
        parent::setUp();
        $this->manager = new AdvancedSessionManager();

        $this->loadMigrationsFrom(__DIR__.'/../../database/migrations');
        $this->loadMigrationsFrom(__DIR__.'/../../database/migrations/authentication');
    }

    protected function getEnvironmentSetUp($app): void
    {
        $app['config']->set('database.default', 'testing');
        $app['config']->set('database.connections.testing', [
            'driver' => 'sqlite',
            'database' => ':memory:',
            'prefix' => '',
        ]);

        $app['config']->set('artisanpack.security.advanced_sessions', [
            'enabled' => true,
            'binding' => [
                'enabled' => true,
                'bind_to_ip' => false,
                'bind_to_ip_range' => true,
                'bind_to_user_agent' => true,
            ],
            'concurrency' => [
                'enabled' => true,
                'max_sessions' => 5,
            ],
            'expiration' => [
                'idle_timeout_minutes' => 60,
                'absolute_timeout_hours' => 24,
            ],
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
    public function it_can_check_if_session_is_expired(): void
    {
        $expiredSession = new UserSession([
            'expires_at' => now()->subHour(),
        ]);

        $activeSession = new UserSession([
            'expires_at' => now()->addHour(),
        ]);

        $this->assertTrue($this->manager->isSessionExpired($expiredSession));
        $this->assertFalse($this->manager->isSessionExpired($activeSession));
    }

    /** @test */
    public function it_validates_session_bindings(): void
    {
        $session = new UserSession([
            'ip_address' => '192.168.1.1',
            'user_agent' => 'Mozilla/5.0 Chrome',
        ]);

        $request = Request::create('/', 'GET', [], [], [], [
            'HTTP_USER_AGENT' => 'Mozilla/5.0 Chrome',
            'REMOTE_ADDR' => '192.168.1.1',
        ]);

        $validation = $this->manager->validateSessionBindings($session, $request);

        $this->assertIsArray($validation);
        $this->assertArrayHasKey('valid', $validation);
        $this->assertArrayHasKey('violations', $validation);
    }

    /** @test */
    public function it_detects_user_agent_mismatch(): void
    {
        $session = new UserSession([
            'ip_address' => '192.168.1.1',
            'user_agent' => 'Mozilla/5.0 Chrome',
        ]);

        $request = Request::create('/', 'GET', [], [], [], [
            'HTTP_USER_AGENT' => 'Mozilla/5.0 Firefox',
            'REMOTE_ADDR' => '192.168.1.1',
        ]);

        $validation = $this->manager->validateSessionBindings($session, $request);

        $this->assertFalse($validation['valid']);
        $this->assertContains('user_agent_mismatch', $validation['violations']);
    }
}
