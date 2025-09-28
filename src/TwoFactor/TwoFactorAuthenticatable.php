<?php
/**
 * Two-Factor Authenticatable Trait
 *
 * Provides the necessary properties and methods to enable two-factor
 * authentication on a user model.
 *
 * @link       https://gitlab.com/jacob-martella-web-design/artisanpack-ui/artisanpack-ui-security
 *
 * @package    ArtisanPackUI\Security
 * @subpackage ArtisanPackUI\Security\TwoFactor
 * @since      1.2.0
 */

namespace ArtisanPackUI\Security\TwoFactor;

use Illuminate\Support\Collection;
use PragmaRX\Google2FA\Google2FA;

/**
 * Provides two-factor authentication capabilities to a model.
 *
 * @since 1.2.0
 *
 * @property-read bool        $two_factor_enabled
 * @property      string|null $two_factor_secret
 * @property      string|null $two_factor_recovery_codes
 * @property      string|null $two_factor_enabled_at
 */
trait TwoFactorAuthenticatable
{
	/**
	 * Get the two_factor_enabled attribute.
	 *
	 * @since 1.2.0
	 *
	 * @return bool
	 */
	public function getTwoFactorEnabledAttribute(): bool
	{
		return $this->hasTwoFactorEnabled();
	}

	/**
	 * Determine if two-factor authentication is enabled.
	 *
	 * @since 1.2.0
	 *
	 * @return bool True if 2FA is enabled, false otherwise.
	 */
	public function hasTwoFactorEnabled(): bool
	{
		return ! is_null( $this->two_factor_enabled_at );
	}

	/**
	 * Generates a new secret key for authenticator-based 2FA.
	 *
	 * @since 1.2.0
	 *
	 * @return void
	 */
	public function generateTwoFactorSecret(): void
	{
		$google2fa = app( Google2FA::class );

		$this->two_factor_secret = encrypt( $google2fa->generateSecretKey() );
		$this->save();
	}

	/**
	 * Generates a new set of recovery codes.
	 *
	 * @since 1.2.0
	 *
	 * @return void
	 */
	public function generateRecoveryCodes(): void
	{
		$this->two_factor_recovery_codes = encrypt(
			json_encode(
				Collection::times( 8, function () {
					return bin2hex( random_bytes( 8 ) );
				} )->all()
			)
		);
		$this->save();
	}
}