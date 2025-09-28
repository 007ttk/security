<?php

use ArtisanPackUI\Security\TwoFactor\Providers\EmailProvider;

return [

	'routes' => [
		/*
		 * The route name where users will be redirected to enter their 2FA code.
		 * The consuming application is responsible for creating this route and view.
		 */
		'verify' => 'two-factor.challenge',
	],

	'two_factor' => [
		/*
		 * The default two-factor authentication provider. This provider will be
		 * used for all 2FA operations unless a different provider is specified.
		 *
		 * Supported: "email"
		 */
		'default'   => env( 'TWO_FACTOR_PROVIDER', 'email' ),

		/*
		 * Here you may configure the providers for two-factor authentication.
		 * You can add your own providers here, but they must implement the
		 * `TwoFactorProvider` interface.
		 */
		'providers' => [

			'email' => [
				'driver' => EmailProvider::class,
			],

		],
	],
];