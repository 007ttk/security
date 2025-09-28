<?php
/**
 * Email-based Two-Factor Provider
 *
 * Handles two-factor authentication by generating a code, storing it in the
 * session, and emailing it to the user.
 *
 * @link       https://gitlab.com/jacob-martella-web-design/artisanpack-ui/artisanpack-ui-security
 *
 * @package    ArtisanPackUI\Security
 * @subpackage ArtisanPackUI\Security\TwoFactor\Providers
 * @since      1.2.0
 */

namespace ArtisanPackUI\Security\TwoFactor\Providers;

use ArtisanPackUI\Security\Mail\TwoFactorCodeMailable;
use ArtisanPackUI\Security\TwoFactor\Contracts\TwoFactorProvider;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\Mail;

/**
 * Implements email-based two-factor authentication.
 *
 * @since 1.2.0
 */
class EmailProvider implements TwoFactorProvider
{
	/**
	 * Generate and dispatch a two-factor authentication challenge to the user.
	 *
	 * @since 1.2.0
	 *
	 * @param Authenticatable $user The user to send the challenge to.
	 * @return void
	 */
	public function generateChallenge( Authenticatable $user ): void
	{
		$code = random_int( 100000, 999999 );

		session( [
					 'two_factor_code'    => $code,
					 'two_factor_expires' => now()->addMinutes( 10 ),
					 'two_factor_user_id' => $user->getAuthIdentifier(),
				 ] );

		Mail::to( $user->email )->send( new TwoFactorCodeMailable( $code ) );
	}

	/**
	 * Verify a given two-factor authentication code.
	 *
	 * @since 1.2.0
	 *
	 * @param Authenticatable $user The user attempting to verify.
	 * @param string          $code The code provided by the user.
	 * @return bool True if the code is valid, false otherwise.
	 */
	public function verify( Authenticatable $user, string $code ): bool
	{
		if (
			session( 'two_factor_user_id' ) !== $user->getAuthIdentifier() ||
			now()->isAfter( session( 'two_factor_expires' ) ) ||
			! hash_equals( (string) session( 'two_factor_code' ), $code )
		) {
			return false;
		}

		session()->forget( [ 'two_factor_code', 'two_factor_expires', 'two_factor_user_id' ] );

		return true;
	}
}