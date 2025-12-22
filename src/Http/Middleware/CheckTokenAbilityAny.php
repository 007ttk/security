<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Http\Middleware;

use ArtisanPackUI\Security\Contracts\SecurityEventLoggerInterface;
use ArtisanPackUI\Security\Models\SecurityEvent;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class CheckTokenAbilityAny
{
    public function __construct(
        protected ?SecurityEventLoggerInterface $logger = null
    ) {}

    /**
     * Handle an incoming request.
     *
     * Check if the current token has ANY of the required abilities.
     *
     * Usage:
     *   ->middleware('token.ability.any:write,admin')
     */
    public function handle(Request $request, Closure $next, ...$abilities): Response
    {
        if (empty($abilities)) {
            return $next($request);
        }

        $user = $request->user();

        if (! $user) {
            $this->logApiAccessFailure('ability_denied_unauthenticated', [
                'required_abilities' => $abilities,
                'reason' => 'unauthenticated',
            ]);

            return response()->json([
                'message' => 'Unauthenticated.',
                'error' => 'unauthenticated',
            ], 401);
        }

        $token = $user->currentAccessToken();

        if (! $token) {
            $this->logApiAccessFailure('ability_denied_no_token', [
                'user_id' => $user->getAuthIdentifier(),
                'required_abilities' => $abilities,
                'reason' => 'no_token',
            ]);

            return response()->json([
                'message' => 'No access token present.',
                'error' => 'no_token',
            ], 401);
        }

        // Check if token has any of the required abilities
        foreach ($abilities as $ability) {
            if ($this->tokenHasAbility($token, $ability)) {
                return $next($request);
            }
        }

        $this->logApiAccessFailure('ability_denied', [
            'user_id' => $user->getAuthIdentifier(),
            'token_id' => $token->id ?? null,
            'required_abilities' => $abilities,
            'reason' => 'insufficient_ability',
        ]);

        return response()->json([
            'message' => 'Token does not have any of the required abilities.',
            'error' => 'insufficient_ability',
            'required_abilities' => $abilities,
        ], 403);
    }

    /**
     * Check if the token has a specific ability.
     */
    protected function tokenHasAbility($token, string $ability): bool
    {
        // Use our extended method if available
        if (method_exists($token, 'hasAbility')) {
            return $token->hasAbility($ability);
        }

        // Fallback to Sanctum's standard behavior
        $abilities = $token->abilities ?? [];

        return in_array('*', $abilities, true)
            || in_array($ability, $abilities, true);
    }

    /**
     * Log an API access failure event.
     */
    protected function logApiAccessFailure(string $event, array $data): void
    {
        if ($this->logger === null) {
            return;
        }

        $this->logger->apiAccess($event, $data, SecurityEvent::SEVERITY_WARNING);
    }
}
