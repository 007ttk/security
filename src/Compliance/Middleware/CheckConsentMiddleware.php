<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Compliance\Middleware;

use ArtisanPackUI\Security\Compliance\Consent\ConsentManager;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class CheckConsentMiddleware
{
    public function __construct(protected ConsentManager $consentManager) {}

    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     */
    public function handle(Request $request, Closure $next, string $purpose): Response
    {
        $user = $request->user();

        if (! $user) {
            return $next($request);
        }

        $verification = $this->consentManager->verifyConsent($user->id, $purpose);

        if (! $verification->isValid) {
            if ($verification->requiresReconsent) {
                return response()->json([
                    'error' => 'reconsent_required',
                    'message' => 'Please update your consent preferences.',
                    'purpose' => $purpose,
                ], 403);
            }

            return response()->json([
                'error' => 'consent_required',
                'message' => 'Consent is required to access this resource.',
                'purpose' => $purpose,
            ], 403);
        }

        return $next($request);
    }
}
