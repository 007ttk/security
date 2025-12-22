<?php

namespace Tests\Feature;

use ArtisanPackUI\Security\Models\Permission;
use ArtisanPackUI\Security\Models\Role;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Route;
use Orchestra\Testbench\TestCase;
use PHPUnit\Framework\Attributes\Test;
use Tests\Models\TestUser;

class RbacTest extends TestCase
{
    protected function getPackageProviders($app)
    {
        return [
            \ArtisanPackUI\Security\SecurityServiceProvider::class,
        ];
    }

    protected function getEnvironmentSetUp($app)
    {
        Config::set('artisanpack.security.rbac.enabled', true);
        Config::set('database.default', 'testbench');
        Config::set('database.connections.testbench', [
            'driver'   => 'sqlite',
            'database' => ':memory:',
            'prefix'   => '',
        ]);

        Config::set('auth.providers.users.model', TestUser::class);

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
    public function it_can_create_a_role()
    {
        $this->artisan('role:create', ['name' => 'admin']);

        $this->assertDatabaseHas('roles', ['name' => 'admin']);
    }

    #[Test]
    public function it_can_create_a_permission()
    {
        $this->artisan('permission:create', ['name' => 'edit-articles']);

        $this->assertDatabaseHas('permissions', ['name' => 'edit-articles']);
    }

    #[Test]
    public function it_can_assign_a_role_to_a_user()
    {
        $user = TestUser::create(['name' => 'Test User', 'email' => 'test@example.com']);
        $role = Role::create(['name' => 'admin']);

        // Assign the role once
        $this->artisan('user:assign-role', ['user' => $user->id, 'role' => 'admin']);
        $user->refresh();
        $this->assertTrue($user->hasRole('admin'));
        $this->assertCount(1, $user->roles); // Assert only one role assigned

        // Assign the role again
        $this->artisan('user:assign-role', ['user' => $user->id, 'role' => 'admin']);
        $user->refresh();
        $this->assertTrue($user->hasRole('admin'));
        $this->assertCount(1, $user->roles); // Assert still only one role assigned
    }

    #[Test]
    public function it_can_revoke_a_role_from_a_user()
    {
        $user = TestUser::create(['name' => 'Test User', 'email' => 'test@example.com']);
        $role = Role::create(['name' => 'admin']);
        $user->roles()->attach($role);

        $this->artisan('user:revoke-role', ['user' => $user->id, 'role' => 'admin']);

        $user->refresh();
        $this->assertFalse($user->hasRole('admin'));
    }

    #[Test]
    public function a_user_has_a_role()
    {
        $user = TestUser::create(['name' => 'Test User', 'email' => 'test@example.com']);
        $role = Role::create(['name' => 'admin']);
        $user->roles()->attach($role);

        $this->assertTrue($user->hasRole('admin'));
        $this->assertFalse($user->hasRole('moderator'));
    }

    #[Test]
    public function a_user_has_a_permission()
    {
        $user = TestUser::create(['name' => 'Test User', 'email' => 'test@example.com']);
        $role = Role::create(['name' => 'admin']);
        $permission = Permission::create(['name' => 'edit-articles']);
        $role->permissions()->attach($permission);
        $user->roles()->attach($role);

        $this->assertTrue($user->hasPermission('edit-articles'));
        $this->assertFalse($user->hasPermission('delete-articles'));
    }

    #[Test]
    public function a_user_has_a_permission_through_role_inheritance()
    {
        $user = TestUser::create(['name' => 'Test User', 'email' => 'test@example.com']);
        $adminRole = Role::create(['name' => 'admin']);
        $editorRole = Role::create(['name' => 'editor', 'parent_id' => $adminRole->id]);
        $permission = Permission::create(['name' => 'edit-articles']);
        $adminRole->permissions()->attach($permission);
        $user->roles()->attach($editorRole);

        $this->assertTrue($user->hasPermission('edit-articles'));
    }

    #[Test]
    public function it_blocks_a_user_without_permission_from_a_route()
    {
        $user = TestUser::create(['name' => 'Test User', 'email' => 'test@example.com']);
        $this->actingAs($user);

        Route::get('/protected-route', function () {
            return 'Success';
        })->middleware('permission:edit-articles');

        $response = $this->get('/protected-route');
        $response->assertStatus(403);
    }

    #[Test]
    public function it_allows_a_user_with_permission_to_a_route()
    {
        $user = TestUser::create(['name' => 'Test User', 'email' => 'test@example.com']);
        $role = Role::create(['name' => 'admin']);
        $permission = Permission::create(['name' => 'edit-articles']);
        $role->permissions()->attach($permission);
        $user->roles()->attach($role);

        $this->actingAs($user);

        Route::get('/protected-route', function () {
            return 'Success';
        })->middleware('permission:edit-articles');

        $response = $this->get('/protected-route');
        $response->assertStatus(200);
    }

    #[Test]
    public function the_role_blade_directive_works()
    {
        $user = TestUser::create(['name' => 'Test User', 'email' => 'test@example.com']);
        $role = Role::create(['name' => 'admin']);
        $user->roles()->attach($role);
        $this->actingAs($user);

        $view = view()->file(__DIR__ . '/../views/role-directive.blade.php')->render();

        $this->assertStringContainsString('User is an admin', $view);
        $this->assertStringNotContainsString('User is a moderator', $view);
    }

    #[Test]
    public function the_permission_blade_directive_works()
    {
        $user = TestUser::create(['name' => 'Test User', 'email' => 'test@example.com']);
        $role = Role::create(['name' => 'admin']);
        $permission = Permission::create(['name' => 'edit-articles']);
        $role->permissions()->attach($permission);
        $user->roles()->attach($role);

        $this->actingAs($user);

        $view = view()->file(__DIR__ . '/../views/permission-directive.blade.php')->render();

        $this->assertStringContainsString('User can edit articles', $view);
        $this->assertStringNotContainsString('User can delete articles', $view);
    }
}