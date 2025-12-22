<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Http\Middleware;

use ArtisanPackUI\Security\Contracts\SecurityEventLoggerInterface;
use ArtisanPackUI\Security\Models\SecurityEvent;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class CheckPermission
{
    public function __construct(
        protected ?SecurityEventLoggerInterface $logger = null
    ) {}

    public function handle(Request $request, Closure $next, $permission)
    {
        if (Auth::guest()) {
            $this->logAuthorizationFailure('permission_denied_guest', [
                'permission' => $permission,
                'reason' => 'unauthenticated',
            ]);
            abort(401);
        }

        if (! Auth::user()->can($permission)) {
            $this->logAuthorizationFailure('permission_denied', [
                'permission' => $permission,
                'user_id' => Auth::id(),
                'reason' => 'insufficient_permissions',
            ]);
            abort(403);
        }

        return $next($request);
    }

    /**
     * Log an authorization failure event.
     */
    protected function logAuthorizationFailure(string $event, array $data): void
    {
        if ($this->logger === null) {
            return;
        }

        $this->logger->authorization($event, $data, SecurityEvent::SEVERITY_WARNING);
    }
}
