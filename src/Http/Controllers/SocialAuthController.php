<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Http\Controllers;

use ArtisanPackUI\Security\Authentication\Social\SocialAuthManager;
use ArtisanPackUI\Security\Events\SocialAccountLinked;
use ArtisanPackUI\Security\Events\SocialLoginSucceeded;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Auth;

class SocialAuthController extends Controller
{
    /**
     * Create a new controller instance.
     */
    public function __construct(
        protected SocialAuthManager $socialAuthManager
    ) {}

    /**
     * Redirect to the OAuth provider.
     */
    public function redirect(Request $request, string $provider): RedirectResponse
    {
        if (! config('security.social.enabled', false)) {
            abort(404, 'Social authentication is not enabled');
        }

        if (! $this->socialAuthManager->hasProvider($provider)) {
            abort(404, 'Social provider not found');
        }

        $options = [];

        // Pass through any additional options from query string
        if ($request->has('prompt')) {
            $options['prompt'] = $request->input('prompt');
        }

        $url = $this->socialAuthManager->redirect($provider, $options);

        return redirect()->away($url);
    }

    /**
     * Handle the OAuth callback.
     */
    public function callback(Request $request, string $provider): RedirectResponse
    {
        if (! config('security.social.enabled', false)) {
            abort(404, 'Social authentication is not enabled');
        }

        // Check for errors
        if ($request->has('error')) {
            return redirect()->route('login')
                ->with('error', 'Authentication was cancelled or failed: '.$request->input('error_description', $request->input('error')));
        }

        $code = $request->input('code');
        $state = $request->input('state');

        if (empty($code)) {
            return redirect()->route('login')
                ->with('error', 'No authorization code received');
        }

        try {
            $result = $this->socialAuthManager->callback($provider, $code, $state);
            $socialUser = $result['user'];
            $tokens = $result['tokens'];

            // If user is already authenticated, link the account
            if (Auth::check()) {
                $this->socialAuthManager->linkIdentity(Auth::user(), $socialUser, $tokens);
                event(new SocialAccountLinked(Auth::user(), $provider, $socialUser));

                return redirect()->intended(config('security.social.redirect_after_link', '/settings'))
                    ->with('success', ucfirst($provider).' account linked successfully');
            }

            // Find or create user
            $user = $this->socialAuthManager->findOrCreateUser($socialUser, $tokens);

            if (! $user) {
                return redirect()->route('login')
                    ->with('error', 'Unable to authenticate with '.ucfirst($provider));
            }

            // Log the user in
            Auth::login($user, remember: true);
            $request->session()->regenerate();

            event(new SocialLoginSucceeded($user, $provider, $socialUser));

            return redirect()->intended(config('security.social.redirect_after_login', '/dashboard'))
                ->with('success', 'Logged in successfully with '.ucfirst($provider));
        } catch (\Exception $e) {
            report($e);

            return redirect()->route('login')
                ->with('error', 'Authentication failed. Please try again.');
        }
    }

    /**
     * Link a social account to the current user.
     */
    public function link(Request $request, string $provider): RedirectResponse
    {
        if (! Auth::check()) {
            return redirect()->route('login');
        }

        if (! config('security.social.allow_linking', true)) {
            return back()->with('error', 'Account linking is not enabled');
        }

        // Redirect to OAuth flow, callback will handle linking
        return $this->redirect($request, $provider);
    }

    /**
     * Unlink a social account from the current user.
     */
    public function unlink(Request $request, string $provider): RedirectResponse
    {
        if (! Auth::check()) {
            return redirect()->route('login');
        }

        try {
            $this->socialAuthManager->unlinkIdentity(Auth::user(), $provider);

            return back()->with('success', ucfirst($provider).' account unlinked successfully');
        } catch (\Exception $e) {
            return back()->with('error', $e->getMessage());
        }
    }
}
