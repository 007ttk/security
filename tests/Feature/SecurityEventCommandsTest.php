<?php

namespace Tests\Feature;

use ArtisanPackUI\Security\Models\SecurityEvent;
use Illuminate\Support\Facades\Config;
use Orchestra\Testbench\TestCase;
use PHPUnit\Framework\Attributes\Test;

class SecurityEventCommandsTest extends TestCase
{
    protected function getPackageProviders($app)
    {
        return [
            \ArtisanPackUI\Security\SecurityServiceProvider::class,
        ];
    }

    protected function getEnvironmentSetUp($app)
    {
        Config::set('artisanpack.security.enabled', false);
        Config::set('artisanpack.security.eventLogging.enabled', true);
        Config::set('artisanpack.security.eventLogging.storage.database', true);
        Config::set('database.default', 'testbench');
        Config::set('database.connections.testbench', [
            'driver' => 'sqlite',
            'database' => ':memory:',
            'prefix' => '',
        ]);

        // Create users table for migrations that depend on it
        $app['db']->connection()->getSchemaBuilder()->create('users', function ($table) {
            $table->increments('id');
            $table->string('name');
            $table->string('email');
            $table->timestamps();
        });
    }

    public function setUp(): void
    {
        parent::setUp();
        $this->artisan('migrate', ['--database' => 'testbench'])->run();
    }

    #[Test]
    public function it_can_list_security_events()
    {
        // Create some events
        SecurityEvent::create([
            'event_type' => SecurityEvent::TYPE_AUTHENTICATION,
            'event_name' => 'login_success',
            'severity' => SecurityEvent::SEVERITY_INFO,
            'ip_address' => '127.0.0.1',
        ]);

        $this->artisan('security:events:list')
            ->assertSuccessful();
    }

    #[Test]
    public function it_can_filter_events_by_type()
    {
        SecurityEvent::create([
            'event_type' => SecurityEvent::TYPE_AUTHENTICATION,
            'event_name' => 'login_success',
            'severity' => SecurityEvent::SEVERITY_INFO,
            'ip_address' => '127.0.0.1',
        ]);

        $this->artisan('security:events:list', ['--type' => 'authentication'])
            ->assertSuccessful();
    }

    #[Test]
    public function it_can_clear_old_events()
    {
        // Create an old event using DB query to set timestamp correctly
        \Illuminate\Support\Facades\DB::table('security_events')->insert([
            'event_type' => SecurityEvent::TYPE_AUTHENTICATION,
            'event_name' => 'old_event',
            'severity' => SecurityEvent::SEVERITY_INFO,
            'ip_address' => '127.0.0.1',
            'created_at' => now()->subDays(100)->toDateTimeString(),
        ]);

        $this->artisan('security:events:clear', ['--force' => true, '--days' => 90])
            ->assertSuccessful();

        $this->assertDatabaseMissing('security_events', ['event_name' => 'old_event']);
    }

    #[Test]
    public function it_can_export_events_to_csv()
    {
        SecurityEvent::create([
            'event_type' => SecurityEvent::TYPE_AUTHENTICATION,
            'event_name' => 'login_success',
            'severity' => SecurityEvent::SEVERITY_INFO,
            'ip_address' => '127.0.0.1',
        ]);

        $path = storage_path('test-export.csv');

        $this->artisan('security:events:export', ['path' => $path])
            ->assertSuccessful();

        $this->assertFileExists($path);
        unlink($path);
    }

    #[Test]
    public function it_can_export_events_to_json()
    {
        SecurityEvent::create([
            'event_type' => SecurityEvent::TYPE_AUTHENTICATION,
            'event_name' => 'login_success',
            'severity' => SecurityEvent::SEVERITY_INFO,
            'ip_address' => '127.0.0.1',
        ]);

        $path = storage_path('test-export.json');

        $this->artisan('security:events:export', ['path' => $path, '--format' => 'json'])
            ->assertSuccessful();

        $this->assertFileExists($path);
        $content = file_get_contents($path);
        $this->assertJson($content);
        unlink($path);
    }

    #[Test]
    public function it_can_show_statistics()
    {
        SecurityEvent::create([
            'event_type' => SecurityEvent::TYPE_AUTHENTICATION,
            'event_name' => 'login_success',
            'severity' => SecurityEvent::SEVERITY_INFO,
            'ip_address' => '127.0.0.1',
        ]);

        SecurityEvent::create([
            'event_type' => SecurityEvent::TYPE_AUTHENTICATION,
            'event_name' => 'login_failed',
            'severity' => SecurityEvent::SEVERITY_WARNING,
            'ip_address' => '127.0.0.1',
        ]);

        $this->artisan('security:events:stats')
            ->assertSuccessful();
    }

    #[Test]
    public function it_can_detect_suspicious_activity()
    {
        // Create multiple failed logins from same IP
        for ($i = 0; $i < 10; $i++) {
            SecurityEvent::create([
                'event_type' => SecurityEvent::TYPE_AUTHENTICATION,
                'event_name' => 'login_failed',
                'severity' => SecurityEvent::SEVERITY_WARNING,
                'ip_address' => '192.168.1.1',
            ]);
        }

        $this->artisan('security:detect')
            ->assertSuccessful();
    }
}
