<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Http\Controllers;

use ArtisanPackUI\Security\Authentication\Sso\SsoManager;
use ArtisanPackUI\Security\Events\SsoLoginSucceeded;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Auth;

class SsoController extends Controller
{
    /**
     * Create a new controller instance.
     */
    public function __construct(
        protected SsoManager $ssoManager
    ) {}

    /**
     * Initiate SSO login.
     */
    public function initiate(Request $request, string $idp): RedirectResponse
    {
        if (! config('security.sso.enabled', false)) {
            abort(404, 'SSO is not enabled');
        }

        $options = [
            'relay_state' => $request->input('redirect_to', url()->previous()),
        ];

        try {
            $loginUrl = $this->ssoManager->login($idp, $options);

            return redirect()->away($loginUrl);
        } catch (\Exception $e) {
            report($e);

            return redirect()->route('login')
                ->with('error', 'SSO initiation failed. Please try again or contact support.');
        }
    }

    /**
     * Handle SAML Assertion Consumer Service (ACS).
     */
    public function assertionConsumer(Request $request, string $idp): RedirectResponse
    {
        return $this->handleCallback($request, $idp);
    }

    /**
     * Handle OIDC callback.
     */
    public function callback(Request $request, string $idp): RedirectResponse
    {
        return $this->handleCallback($request, $idp);
    }

    /**
     * Handle the SSO callback.
     */
    protected function handleCallback(Request $request, string $idp): RedirectResponse
    {
        if (! config('security.sso.enabled', false)) {
            abort(404, 'SSO is not enabled');
        }

        try {
            $ssoUser = $this->ssoManager->callback($idp, $request);

            // Find or create user (JIT provisioning)
            $user = $this->ssoManager->findOrCreateUser($ssoUser);

            if (! $user) {
                return redirect()->route('login')
                    ->with('error', 'Unable to authenticate via SSO');
            }

            // Update attributes if configured
            $this->ssoManager->updateUserAttributes($user, $ssoUser);

            // Log the user in
            Auth::login($user, remember: true);
            $request->session()->regenerate();

            event(new SsoLoginSucceeded($user, $idp, $ssoUser));

            // Redirect to relay state or default
            $redirectTo = $request->input('RelayState', config('security.sso.redirect_after_login', '/dashboard'));

            return redirect()->to($redirectTo)
                ->with('success', 'Logged in successfully via SSO');
        } catch (\Exception $e) {
            report($e);

            return redirect()->route('login')
                ->with('error', 'SSO authentication failed. Please try again or contact support.');
        }
    }

    /**
     * Handle SSO logout.
     */
    public function logout(Request $request, string $idp): RedirectResponse
    {
        if (! Auth::check()) {
            return redirect()->route('login');
        }

        $user = Auth::user();
        $options = $this->ssoManager->getLogoutOptions($user, $idp);

        // Get SLO URL
        $sloUrl = $this->ssoManager->logout($idp, $options);

        // Log the user out locally
        Auth::logout();
        $request->session()->invalidate();
        $request->session()->regenerateToken();

        // If provider supports SLO, redirect to IdP
        if ($sloUrl) {
            return redirect()->away($sloUrl);
        }

        return redirect()->route('login')
            ->with('success', 'Logged out successfully');
    }

    /**
     * Return SP metadata for SAML.
     */
    public function metadata(string $idp): Response
    {
        if (! config('security.sso.enabled', false)) {
            abort(404, 'SSO is not enabled');
        }

        try {
            $metadata = $this->ssoManager->getMetadata($idp);

            if (! $metadata) {
                abort(404, 'Metadata not available for this provider');
            }

            return response($metadata, 200, [
                'Content-Type' => 'application/xml',
            ]);
        } catch (\Exception $e) {
            report($e);
            abort(500, 'Failed to generate metadata');
        }
    }
}
