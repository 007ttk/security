<?php

namespace Tests\Feature;

use ArtisanPackUI\Security\Http\Middleware\CheckAccountLockout;
use ArtisanPackUI\Security\Http\Middleware\StepUpAuthentication;
use ArtisanPackUI\Security\Authentication\Lockout\AccountLockoutManager;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Tests\Models\TestUser;
use Tests\TestCase;

class AuthenticationMiddlewareTest extends TestCase
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
        $app['config']->set('database.default', 'testing');
        $app['config']->set('database.connections.testing', [
            'driver' => 'sqlite',
            'database' => ':memory:',
            'prefix' => '',
        ]);

        $app['config']->set('artisanpack.security.account_lockout.enabled', true);
        $app['config']->set('artisanpack.security.step_up_authentication.enabled', true);
        $app['config']->set('artisanpack.security.step_up_authentication.timeout_minutes', 15);

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
    public function check_account_lockout_allows_unlocked_requests(): void
    {
        $lockoutManager = $this->app->make(AccountLockoutManager::class);
        $middleware = new CheckAccountLockout($lockoutManager);

        $request = Request::create('/', 'GET');
        $request->server->set('REMOTE_ADDR', '192.168.1.1');

        $response = $middleware->handle($request, function () {
            return new Response('OK');
        });

        $this->assertEquals('OK', $response->getContent());
    }

    /** @test */
    public function step_up_authentication_requires_recent_verification(): void
    {
        $middleware = new StepUpAuthentication();

        $request = Request::create('/', 'GET');
        $request->setLaravelSession($this->app['session.store']);

        // Simulate an authenticated user
        $this->actingAs($this->createMockUser());

        $response = $middleware->handle($request, function () {
            return new Response('OK');
        });

        // Should redirect or require step-up since no recent verification
        $this->assertNotEquals('OK', $response->getContent());
    }

    /** @test */
    public function step_up_authentication_allows_recently_verified(): void
    {
        $middleware = new StepUpAuthentication();

        $request = Request::create('/', 'GET');
        $session = $this->app['session.store'];
        $session->put('step_up_authenticated_at', now());
        $request->setLaravelSession($session);

        $this->actingAs($this->createMockUser());

        $response = $middleware->handle($request, function () {
            return new Response('OK');
        });

        $this->assertEquals('OK', $response->getContent());
    }

    protected function createMockUser()
    {
        return TestUser::create([
            'name' => 'Test User',
            'email' => 'test@example.com',
            'password' => bcrypt('password'),
        ]);
    }
}
