<?php

namespace Tests\Feature;

use ArtisanPackUI\Security\Contracts\SecurityEventLoggerInterface;
use ArtisanPackUI\Security\Models\Permission;
use ArtisanPackUI\Security\Models\Role;
use ArtisanPackUI\Security\Models\SecurityEvent;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Route;
use Orchestra\Testbench\TestCase;
use PHPUnit\Framework\Attributes\Test;
use Tests\Models\TestUser;

class SecurityEventLoggingTest extends TestCase
{
    protected function getPackageProviders($app)
    {
        return [
            \ArtisanPackUI\Security\SecurityServiceProvider::class,
        ];
    }

    protected function getEnvironmentSetUp($app)
    {
        Config::set('artisanpack.security.eventLogging.enabled', true);
        Config::set('artisanpack.security.eventLogging.storage.database', true);
        Config::set('artisanpack.security.rbac.enabled', true);
        Config::set('database.default', 'testbench');
        Config::set('database.connections.testbench', [
            'driver' => 'sqlite',
            'database' => ':memory:',
            'prefix' => '',
        ]);

        Config::set('auth.providers.users.model', TestUser::class);

        $app['db']->connection()->getSchemaBuilder()->create('users', function ($table) {
            $table->increments('id');
            $table->string('name');
            $table->string('email');
            $table->timestamps();
        });

        // Create pivot tables required for Role model boot cleanup
        // Note: Laravel uses alphabetical ordering for pivot table names
        // With TestUser model, the pivot becomes 'role_test_user'
        $app['db']->connection()->getSchemaBuilder()->create('role_test_user', function ($table) {
            $table->unsignedBigInteger('role_id');
            $table->unsignedBigInteger('test_user_id');
            $table->primary(['role_id', 'test_user_id']);
        });

        $app['db']->connection()->getSchemaBuilder()->create('permission_role', function ($table) {
            $table->unsignedBigInteger('permission_id');
            $table->unsignedBigInteger('role_id');
            $table->primary(['permission_id', 'role_id']);
        });
    }

    public function setUp(): void
    {
        parent::setUp();
        $this->artisan('migrate', ['--database' => 'testbench'])->run();
    }

    #[Test]
    public function it_logs_permission_denied_events()
    {
        $user = TestUser::create(['name' => 'Test User', 'email' => 'test@example.com']);
        $this->actingAs($user);

        Route::get('/protected-route', function () {
            return 'Success';
        })->middleware('permission:edit-articles');

        $response = $this->get('/protected-route');
        $response->assertStatus(403);

        $this->assertDatabaseHas('security_events', [
            'event_type' => SecurityEvent::TYPE_AUTHORIZATION,
            'event_name' => 'permission_denied',
        ]);
    }

    #[Test]
    public function it_logs_role_created_events()
    {
        $role = Role::create(['name' => 'admin', 'description' => 'Administrator']);

        $this->assertDatabaseHas('security_events', [
            'event_type' => SecurityEvent::TYPE_ROLE_CHANGE,
            'event_name' => 'role_created',
        ]);
    }

    #[Test]
    public function it_logs_role_updated_events()
    {
        $role = Role::create(['name' => 'admin', 'description' => 'Administrator']);
        $role->update(['description' => 'Updated description']);

        $this->assertDatabaseHas('security_events', [
            'event_type' => SecurityEvent::TYPE_ROLE_CHANGE,
            'event_name' => 'role_updated',
        ]);
    }

    #[Test]
    public function it_logs_role_deleted_events()
    {
        $role = Role::create(['name' => 'admin', 'description' => 'Administrator']);
        $role->delete();

        $this->assertDatabaseHas('security_events', [
            'event_type' => SecurityEvent::TYPE_ROLE_CHANGE,
            'event_name' => 'role_deleted',
        ]);
    }

    #[Test]
    public function it_logs_permission_created_events()
    {
        $permission = Permission::create(['name' => 'edit-articles']);

        $this->assertDatabaseHas('security_events', [
            'event_type' => SecurityEvent::TYPE_PERMISSION_CHANGE,
            'event_name' => 'permission_created',
        ]);
    }

    #[Test]
    public function it_logs_permission_updated_events()
    {
        $permission = Permission::create(['name' => 'edit-articles', 'description' => 'Edit']);
        $permission->update(['description' => 'Updated']);

        $this->assertDatabaseHas('security_events', [
            'event_type' => SecurityEvent::TYPE_PERMISSION_CHANGE,
            'event_name' => 'permission_updated',
        ]);
    }

    #[Test]
    public function it_logs_permission_deleted_events()
    {
        $permission = Permission::create(['name' => 'edit-articles']);
        $permission->delete();

        $this->assertDatabaseHas('security_events', [
            'event_type' => SecurityEvent::TYPE_PERMISSION_CHANGE,
            'event_name' => 'permission_deleted',
        ]);
    }
}
