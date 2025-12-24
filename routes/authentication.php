<?php

declare(strict_types=1);

use ArtisanPackUI\Security\Http\Controllers\DeviceController;
use ArtisanPackUI\Security\Http\Controllers\SessionController;
use ArtisanPackUI\Security\Http\Controllers\SocialAuthController;
use ArtisanPackUI\Security\Http\Controllers\SsoController;
use ArtisanPackUI\Security\Http\Controllers\WebAuthnController;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| Social Authentication Routes
|--------------------------------------------------------------------------
*/

Route::prefix('auth/social')->group(function () {
    Route::get('{provider}/redirect', [SocialAuthController::class, 'redirect'])
        ->name('social.redirect');

    Route::get('{provider}/callback', [SocialAuthController::class, 'callback'])
        ->name('social.callback');

    Route::middleware('auth')->group(function () {
        Route::post('{provider}/link', [SocialAuthController::class, 'link'])
            ->name('social.link');

        Route::delete('{provider}/unlink', [SocialAuthController::class, 'unlink'])
            ->name('social.unlink');
    });
});

/*
|--------------------------------------------------------------------------
| SSO Authentication Routes
|--------------------------------------------------------------------------
*/

Route::prefix('auth/sso')->group(function () {
    Route::get('{idp}/login', [SsoController::class, 'initiate'])
        ->name('sso.login');

    Route::post('{idp}/acs', [SsoController::class, 'assertionConsumer'])
        ->name('sso.acs');

    Route::get('{idp}/callback', [SsoController::class, 'callback'])
        ->name('sso.callback');

    Route::match(['get', 'post'], '{idp}/logout', [SsoController::class, 'logout'])
        ->name('sso.logout');

    Route::get('{idp}/metadata', [SsoController::class, 'metadata'])
        ->name('sso.metadata');
});

/*
|--------------------------------------------------------------------------
| WebAuthn Routes
|--------------------------------------------------------------------------
*/

Route::prefix('auth/webauthn')->group(function () {
    // Registration (requires auth)
    Route::middleware('auth')->group(function () {
        Route::post('register/options', [WebAuthnController::class, 'registerOptions'])
            ->name('webauthn.register.options');

        Route::post('register/verify', [WebAuthnController::class, 'registerVerify'])
            ->name('webauthn.register.verify');

        Route::get('credentials', [WebAuthnController::class, 'credentials'])
            ->name('webauthn.credentials');

        Route::patch('credentials/{id}', [WebAuthnController::class, 'updateCredential'])
            ->name('webauthn.credentials.update');

        Route::delete('credentials/{id}', [WebAuthnController::class, 'deleteCredential'])
            ->name('webauthn.credentials.delete');
    });

    // Authentication (no auth required)
    Route::post('authenticate/options', [WebAuthnController::class, 'authenticateOptions'])
        ->name('webauthn.authenticate.options');

    Route::post('authenticate/verify', [WebAuthnController::class, 'authenticateVerify'])
        ->name('webauthn.authenticate.verify');
});

/*
|--------------------------------------------------------------------------
| Device Management Routes
|--------------------------------------------------------------------------
*/

Route::prefix('auth/devices')->middleware('auth')->group(function () {
    Route::get('/', [DeviceController::class, 'index'])
        ->name('devices.index');

    Route::get('current', [DeviceController::class, 'current'])
        ->name('devices.current');

    Route::patch('{device}', [DeviceController::class, 'update'])
        ->name('devices.update');

    Route::post('{device}/trust', [DeviceController::class, 'trust'])
        ->name('devices.trust');

    Route::delete('{device}/revoke', [DeviceController::class, 'revoke'])
        ->name('devices.revoke');
});

/*
|--------------------------------------------------------------------------
| Session Management Routes
|--------------------------------------------------------------------------
*/

Route::prefix('auth/sessions')->middleware('auth')->group(function () {
    Route::get('/', [SessionController::class, 'index'])
        ->name('sessions.index');

    Route::get('current', [SessionController::class, 'current'])
        ->name('sessions.current');

    Route::delete('{session}', [SessionController::class, 'terminate'])
        ->name('sessions.terminate');

    Route::post('terminate-others', [SessionController::class, 'terminateOthers'])
        ->name('sessions.terminate-others');

    Route::post('terminate-all', [SessionController::class, 'terminateAll'])
        ->name('sessions.terminate-all');
});
