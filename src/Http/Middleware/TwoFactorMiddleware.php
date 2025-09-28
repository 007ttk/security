<?php
/**
 * Two-Factor Authentication Middleware
 *
 * Intercepts requests for authenticated users with 2FA enabled to ensure
 * they have completed the verification step.
 *
 * @link       https://gitlab.com/jacob-martella-web-design/artisanpack-ui/artisanpack-ui-security
 *
 * @package    ArtisanPackUI\Security
 * @subpackage ArtisanPackUI\Security\Http\Middleware
 * @since      1.2.0
 */

namespace ArtisanPackUI\Security\Http\Middleware;

use Closure;
use Illuminate\Http\Request;

/**
 * Ensures a user has completed the two-factor authentication challenge.
 *
 * @since 1.2.0
 */
class TwoFactorMiddleware
{
	/**
	 * Handle an incoming request.
	 *
	 * @since 1.2.0
	 *
	 * @param Request $request The incoming request.
	 * @param Closure $next    The next middleware in the chain.
	 * @return mixed
	 */
	public function handle( Request $request, Closure $next ): mixed
	{
		$user = $request->user();

		if ( $user && $user->hasTwoFactorEnabled() && ! $request->session()->get( 'two_factor_verified' ) ) {
			return redirect()->route( config( 'security.routes.verify' ) );
		}

		return $next( $request );
	}
}