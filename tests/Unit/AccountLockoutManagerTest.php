<?php

namespace Tests\Unit;

use ArtisanPackUI\Security\Authentication\Lockout\AccountLockoutManager;
use ArtisanPackUI\Security\Models\AccountLockout;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

class AccountLockoutManagerTest extends TestCase
{
    use RefreshDatabase;

    protected AccountLockoutManager $manager;

    protected function setUp(): void
    {
        parent::setUp();
        $this->manager = new AccountLockoutManager();

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

        $app['config']->set('artisanpack.security.account_lockout', [
            'enabled' => true,
            'max_attempts' => 5,
            'lockout_duration' => 15,
            'progressive' => [
                'enabled' => true,
                'multiplier' => 2.0,
                'max_duration' => 1440,
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
    public function it_can_check_if_ip_is_not_locked(): void
    {
        $this->assertFalse($this->manager->isIpLocked('192.168.1.1'));
    }

    /** @test */
    public function it_can_lock_an_ip_address(): void
    {
        $lockout = $this->manager->lockIp('192.168.1.1', 15, 'Test lockout');

        $this->assertInstanceOf(AccountLockout::class, $lockout);
        $this->assertTrue($this->manager->isIpLocked('192.168.1.1'));
    }

    /** @test */
    public function it_can_unlock_an_ip_address(): void
    {
        $this->manager->lockIp('192.168.1.1', 15, 'Test lockout');
        $this->manager->unlockIp('192.168.1.1');

        $this->assertFalse($this->manager->isIpLocked('192.168.1.1'));
    }

    /** @test */
    public function it_calculates_progressive_lockout_duration(): void
    {
        // First lockout: base duration
        $duration1 = $this->manager->calculateProgressiveDuration(1);
        $this->assertEquals(15, $duration1);

        // Second lockout: multiplied
        $duration2 = $this->manager->calculateProgressiveDuration(2);
        $this->assertEquals(30, $duration2);

        // Third lockout: multiplied again
        $duration3 = $this->manager->calculateProgressiveDuration(3);
        $this->assertEquals(60, $duration3);
    }

    /** @test */
    public function it_respects_max_lockout_duration(): void
    {
        // After many lockouts, should cap at max duration
        $duration = $this->manager->calculateProgressiveDuration(20);

        $maxDuration = config('artisanpack.security.account_lockout.progressive.max_duration', 1440);
        $this->assertLessThanOrEqual($maxDuration, $duration);
    }
}
