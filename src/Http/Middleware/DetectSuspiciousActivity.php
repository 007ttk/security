<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Http\Middleware;

use ArtisanPackUI\Security\Authentication\Detection\SuspiciousActivityService;
use ArtisanPackUI\Security\Events\SuspiciousActivityDetected;
use ArtisanPackUI\Security\Models\SuspiciousActivity;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Symfony\Component\HttpFoundation\Response;

class DetectSuspiciousActivity
{
    /**
     * Create a new middleware instance.
     */
    public function __construct(
        protected SuspiciousActivityService $detector
    ) {}

    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        if (! config('security.suspicious_activity.enabled', true)) {
            return $next($request);
        }

        $user = Auth::user();

        // Analyze the request
        $analysis = $this->detector->analyze($request, $user, [
            'route' => $request->route()?->getName(),
            'method' => $request->method(),
        ]);

        if ($analysis['suspicious']) {
            foreach ($analysis['detections'] as $detection) {
                // Record the suspicious activity
                $activity = $this->detector->record(
                    $request,
                    $detection['type'],
                    $detection['severity'],
                    $analysis['risk_score'],
                    $detection['details'],
                    $user
                );

                // Fire event
                event(new SuspiciousActivityDetected($activity, $request, $user));

                // Take action based on severity
                $action = $this->detector->getRecommendedAction($detection['severity']);
                $response = $this->handleAction($action, $request, $activity);

                if ($response) {
                    return $response;
                }
            }
        }

        return $next($request);
    }

    /**
     * Handle the recommended action.
     */
    protected function handleAction(string $action, Request $request, SuspiciousActivity $activity): ?Response
    {
        switch ($action) {
            case 'block':
                $activity->update(['action_taken' => 'block']);

                if ($request->expectsJson()) {
                    return response()->json([
                        'error' => 'Access denied due to suspicious activity',
                        'activity_id' => $activity->id,
                    ], 403);
                }

                abort(403, 'Access denied due to suspicious activity');

            case 'step_up':
                $activity->update(['action_taken' => 'step_up']);

                if ($request->expectsJson()) {
                    return response()->json([
                        'error' => 'Additional verification required',
                        'require_step_up' => true,
                        'activity_id' => $activity->id,
                    ], 401);
                }

                return redirect()->route('password.confirm')
                    ->with('warning', 'Additional verification is required to continue.');

            case 'captcha':
                $activity->update(['action_taken' => 'captcha']);

                // Store in session that CAPTCHA is required
                session(['require_captcha' => true, 'captcha_reason' => $activity->type]);

                // Continue but the next form submission should require CAPTCHA
                return null;

            case 'lockout':
                $activity->update(['action_taken' => 'lockout']);

                // The lockout will be handled by the CheckAccountLockout middleware
                return null;

            case 'notify':
                $activity->update(['action_taken' => 'notify']);

                // Notification is handled by event listener
                return null;

            default:
                return null;
        }
    }
}
