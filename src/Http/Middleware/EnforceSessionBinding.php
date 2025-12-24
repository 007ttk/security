<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Http\Middleware;

use ArtisanPackUI\Security\Authentication\Session\AdvancedSessionManager;
use ArtisanPackUI\Security\Events\SessionHijackingAttempted;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Symfony\Component\HttpFoundation\Response;

class EnforceSessionBinding
{
    /**
     * Create a new middleware instance.
     */
    public function __construct(
        protected AdvancedSessionManager $sessionManager
    ) {}

    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        if (! config('security.advanced_sessions.enabled', true)) {
            return $next($request);
        }

        $user = Auth::user();
        if (! $user) {
            return $next($request);
        }

        $session = $this->sessionManager->getCurrentSession($request);
        if (! $session) {
            return $next($request);
        }

        // Validate session bindings
        $validation = $this->sessionManager->validateSessionBindings($session, $request);

        if (! $validation['valid']) {
            $hijackingConfig = config('security.advanced_sessions.hijacking_detection', []);

            if ($hijackingConfig['enabled'] ?? true) {
                // Fire event
                event(new SessionHijackingAttempted($user, $session, $request, $validation['violations']));

                $action = $hijackingConfig['action'] ?? 'terminate';

                switch ($action) {
                    case 'terminate':
                        $this->sessionManager->terminateSession($session->id);
                        Auth::logout();
                        $request->session()->invalidate();
                        $request->session()->regenerateToken();

                        if ($request->expectsJson()) {
                            return response()->json([
                                'error' => 'Session terminated due to security violation',
                                'violations' => $validation['violations'],
                            ], 401);
                        }

                        return redirect()->route('login')
                            ->with('error', 'Your session was terminated for security reasons. Please log in again.');

                    case 'require_reauth':
                        if ($request->expectsJson()) {
                            return response()->json([
                                'error' => 'Re-authentication required',
                                'require_reauth' => true,
                            ], 401);
                        }

                        return redirect()->route('password.confirm')
                            ->with('warning', 'Please confirm your password to continue.');

                    case 'notify':
                        // Just log and continue
                        break;
                }
            }
        }

        // Check for session expiration
        if ($this->sessionManager->isSessionExpired($session)) {
            $this->sessionManager->terminateSession($session->id);
            Auth::logout();
            $request->session()->invalidate();
            $request->session()->regenerateToken();

            if ($request->expectsJson()) {
                return response()->json(['error' => 'Session expired'], 401);
            }

            return redirect()->route('login')
                ->with('info', 'Your session has expired. Please log in again.');
        }

        // Touch the session to update activity
        $this->sessionManager->touchSession($session);

        // Check if session should be rotated
        if ($this->sessionManager->shouldRotateSession($session)) {
            $this->sessionManager->rotateSession($session);
        }

        return $next($request);
    }
}
