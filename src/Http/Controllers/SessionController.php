<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Http\Controllers;

use ArtisanPackUI\Security\Authentication\Session\AdvancedSessionManager;
use ArtisanPackUI\Security\Models\UserSession;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Auth;

class SessionController extends Controller
{
    /**
     * Create a new controller instance.
     */
    public function __construct(
        protected AdvancedSessionManager $sessionManager
    ) {}

    /**
     * List all active sessions for the current user.
     */
    public function index(): JsonResponse
    {
        $user = Auth::user();
        if (! $user) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        $sessions = $this->sessionManager->getUserSessions($user);
        $currentSessionId = session()->getId();

        $data = $sessions->map(function (UserSession $session) use ($currentSessionId) {
            $parsedUa = $session->getParsedUserAgent();

            return [
                'id' => $session->id,
                'is_current' => (string) $session->id === $currentSessionId,
                'ip_address' => $session->ip_address,
                'location' => $session->getLocationDisplay(),
                'browser' => $parsedUa['browser'],
                'os' => $parsedUa['os'],
                'auth_method' => $session->auth_method,
                'device_id' => $session->device_id,
                'last_activity_at' => $session->last_activity_at,
                'created_at' => $session->created_at,
            ];
        });

        return response()->json(['sessions' => $data]);
    }

    /**
     * Get the current session.
     */
    public function current(Request $request): JsonResponse
    {
        $user = Auth::user();
        if (! $user) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        $session = $this->sessionManager->getCurrentSession($request);

        if (! $session) {
            return response()->json(['error' => 'Session not found'], 404);
        }

        $parsedUa = $session->getParsedUserAgent();

        return response()->json([
            'session' => [
                'id' => $session->id,
                'ip_address' => $session->ip_address,
                'location' => $session->getLocationDisplay(),
                'browser' => $parsedUa['browser'],
                'os' => $parsedUa['os'],
                'auth_method' => $session->auth_method,
                'last_activity_at' => $session->last_activity_at,
                'expires_at' => $session->expires_at,
                'approaching_idle_timeout' => $this->sessionManager->isApproachingIdleTimeout($session),
            ],
        ]);
    }

    /**
     * Terminate a specific session.
     */
    public function terminate(string $session): JsonResponse
    {
        $user = Auth::user();
        if (! $user) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        // Check if session belongs to user
        $userSession = UserSession::where('user_id', $user->getAuthIdentifier())
            ->where('id', $session)
            ->first();

        if (! $userSession) {
            return response()->json(['error' => 'Session not found'], 404);
        }

        // Don't allow terminating current session through this endpoint
        if ($session === session()->getId()) {
            return response()->json(['error' => 'Cannot terminate current session. Use logout instead.'], 400);
        }

        $this->sessionManager->terminateSession($session);

        return response()->json(['success' => true, 'message' => 'Session terminated']);
    }

    /**
     * Terminate all sessions except the current one.
     */
    public function terminateOthers(Request $request): JsonResponse
    {
        $user = Auth::user();
        if (! $user) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        $currentSessionId = session()->getId();
        $count = $this->sessionManager->terminateOtherSessions($user, $currentSessionId);

        return response()->json([
            'success' => true,
            'message' => "Terminated {$count} other session(s)",
            'terminated_count' => $count,
        ]);
    }

    /**
     * Terminate all sessions (logout from all devices).
     */
    public function terminateAll(Request $request): JsonResponse
    {
        $user = Auth::user();
        if (! $user) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        $count = $this->sessionManager->terminateAllSessions($user);

        // Log out the current user
        Auth::logout();
        $request->session()->invalidate();
        $request->session()->regenerateToken();

        return response()->json([
            'success' => true,
            'message' => "Terminated {$count} session(s)",
            'terminated_count' => $count,
            'redirect' => route('login'),
        ]);
    }
}
