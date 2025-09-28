<?php

namespace ArtisanPackUI\Security;

use ArtisanPackUI\Security\TwoFactor\TwoFactorManager;
use Illuminate\Support\ServiceProvider;

class SecurityServiceProvider extends ServiceProvider
{

	public function register(): void
	{
		$this->app->singleton( 'security', function ( $app ) {
			return new Security();
		} );

		$this->app->singleton( TwoFactorManager::class, function () {
			return new TwoFactorManager();
		} );

		$this->mergeConfigFrom(
			__DIR__ . '/../config/security.php',
			'security'
		);
	}

	/**
	 * Bootstrap services.
	 *
	 * @since 1.0.0
	 *
	 * @return void
	 */
	public function boot(): void
	{
		$this->loadViewsFrom( __DIR__ . '/../resources/views', 'artisanpack-ui-security' );

		if ( $this->app->runningInConsole() ) {
			$this->publishes( [
								  __DIR__ . '/../config/security.php' => config_path( 'security.php' ),
							  ], 'artisanpack-ui-security-config' );

			$this->publishes( [
								  __DIR__ . '/../database/migrations/2025_09_28_205614_add_two_factor_to_users_table.php' => database_path( 'migrations/' . date( 'Y_m_d_His', time() ) . '_add_two_factor_to_users_table.php' ),
							  ], 'artisanpack-ui-security-migrations' );

			$this->publishes( [
								  __DIR__ . '/../resources/views' => resource_path( 'views/vendor/artisanpack-ui-security' ),
							  ], 'artisanpack-ui-views' );
		}
	}
}
