<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Http\Controllers;

use ArtisanPackUI\Security\Authentication\WebAuthn\WebAuthnManager;
use ArtisanPackUI\Security\Events\WebAuthnAuthenticated;
use ArtisanPackUI\Security\Events\WebAuthnRegistered;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Log;

class WebAuthnController extends Controller
{
    /**
     * Create a new controller instance.
     */
    public function __construct(
        protected WebAuthnManager $webAuthnManager
    ) {}

    /**
     * Get registration options.
     */
    public function registerOptions(Request $request): JsonResponse
    {
        if (! config('security.webauthn.enabled', false)) {
            return response()->json(['error' => 'WebAuthn is not enabled'], 404);
        }

        $user = Auth::user();
        if (! $user) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        try {
            $options = $this->webAuthnManager->generateRegistrationOptions($user, $request->all());

            // Store challenge in session
            session(['webauthn_registration_challenge' => $options['challenge']]);

            return response()->json($options);
        } catch (\Exception $e) {
            Log::error('WebAuthn registration options failed', [
                'user_id' => $user->getAuthIdentifier(),
                'error' => $e->getMessage(),
            ]);

            return response()->json([
                'error' => config('app.debug') ? $e->getMessage() : 'Failed to generate registration options',
            ], 500);
        }
    }

    /**
     * Verify registration and store credential.
     */
    public function registerVerify(Request $request): JsonResponse
    {
        if (! config('security.webauthn.enabled', false)) {
            return response()->json(['error' => 'WebAuthn is not enabled'], 404);
        }

        $user = Auth::user();
        if (! $user) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        $validated = $request->validate([
            'id' => 'required|string',
            'rawId' => 'required|string',
            'type' => 'required|string|in:public-key',
            'response.clientDataJSON' => 'required|string',
            'response.attestationObject' => 'required|string',
            'response.transports' => 'array',
            'name' => 'string|max:255',
        ]);

        $challenge = session()->pull('webauthn_registration_challenge');
        if (! $challenge) {
            return response()->json(['error' => 'Registration session expired'], 400);
        }

        try {
            $result = $this->webAuthnManager->verifyRegistration($user, $validated, $challenge);

            if ($result['success']) {
                event(new WebAuthnRegistered($user, $result['credential_id']));

                return response()->json([
                    'success' => true,
                    'message' => 'Security key registered successfully',
                    'credential_id' => $result['credential_id'],
                ]);
            }

            return response()->json([
                'success' => false,
                'error' => $result['error'] ?? 'Registration failed',
            ], 400);
        } catch (\Exception $e) {
            Log::error('WebAuthn registration verification failed', [
                'user_id' => $user->getAuthIdentifier(),
                'error' => $e->getMessage(),
            ]);

            return response()->json([
                'error' => config('app.debug') ? $e->getMessage() : 'Registration verification failed',
            ], 500);
        }
    }

    /**
     * Get authentication options.
     */
    public function authenticateOptions(Request $request): JsonResponse
    {
        if (! config('security.webauthn.enabled', false)) {
            return response()->json(['error' => 'WebAuthn is not enabled'], 404);
        }

        // User might not be authenticated yet (passwordless login)
        $user = Auth::user();

        // If email is provided, find the user
        if (! $user && $request->has('email')) {
            $userModel = config('auth.providers.users.model', 'App\\Models\\User');
            $user = $userModel::where('email', $request->input('email'))->first();
        }

        try {
            $options = $this->webAuthnManager->generateAuthenticationOptions($user, $request->all());

            // Store challenge in session
            session(['webauthn_authentication_challenge' => $options['challenge']]);

            return response()->json($options);
        } catch (\Exception $e) {
            Log::error('WebAuthn authentication options failed', [
                'user_id' => $user?->getAuthIdentifier(),
                'error' => $e->getMessage(),
            ]);

            return response()->json([
                'error' => config('app.debug') ? $e->getMessage() : 'Failed to generate authentication options',
            ], 500);
        }
    }

    /**
     * Verify authentication.
     */
    public function authenticateVerify(Request $request): JsonResponse
    {
        if (! config('security.webauthn.enabled', false)) {
            return response()->json(['error' => 'WebAuthn is not enabled'], 404);
        }

        $validated = $request->validate([
            'id' => 'required|string',
            'rawId' => 'required|string',
            'type' => 'required|string|in:public-key',
            'response.clientDataJSON' => 'required|string',
            'response.authenticatorData' => 'required|string',
            'response.signature' => 'required|string',
            'response.userHandle' => 'nullable|string',
        ]);

        $challenge = session()->pull('webauthn_authentication_challenge');
        if (! $challenge) {
            return response()->json(['error' => 'Authentication session expired'], 400);
        }

        try {
            $result = $this->webAuthnManager->verifyAuthentication($validated, $challenge);

            if ($result['success']) {
                // Log the user in
                $userModel = config('auth.providers.users.model', 'App\\Models\\User');
                $user = $userModel::find($result['user_id']);

                if ($user) {
                    Auth::login($user, remember: true);
                    $request->session()->regenerate();

                    event(new WebAuthnAuthenticated($user));

                    return response()->json([
                        'success' => true,
                        'message' => 'Authenticated successfully',
                        'redirect' => config('security.webauthn.redirect_after_login', '/dashboard'),
                    ]);
                }
            }

            return response()->json([
                'success' => false,
                'error' => $result['error'] ?? 'Authentication failed',
            ], 400);
        } catch (\Exception $e) {
            Log::error('WebAuthn authentication verification failed', [
                'error' => $e->getMessage(),
            ]);

            return response()->json([
                'error' => config('app.debug') ? $e->getMessage() : 'Authentication verification failed',
            ], 500);
        }
    }

    /**
     * List credentials for the current user.
     */
    public function credentials(): JsonResponse
    {
        $user = Auth::user();
        if (! $user) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        $credentials = $this->webAuthnManager->getCredentials($user);

        return response()->json(['credentials' => $credentials]);
    }

    /**
     * Update a credential.
     */
    public function updateCredential(Request $request, int $id): JsonResponse
    {
        $user = Auth::user();
        if (! $user) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        $validated = $request->validate([
            'name' => 'required|string|max:255',
        ]);

        $updated = $this->webAuthnManager->updateCredential($user, $id, $validated);

        if ($updated) {
            return response()->json(['success' => true, 'message' => 'Credential updated']);
        }

        return response()->json(['error' => 'Credential not found'], 404);
    }

    /**
     * Delete a credential.
     */
    public function deleteCredential(int $id): JsonResponse
    {
        $user = Auth::user();
        if (! $user) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        $deleted = $this->webAuthnManager->deleteCredential($user, $id);

        if ($deleted) {
            return response()->json(['success' => true, 'message' => 'Credential deleted']);
        }

        return response()->json(['error' => 'Credential not found'], 404);
    }
}
