<?php

namespace ArtisanPackUI\Security\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use RuntimeException;

class EnsureSessionIsEncrypted
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @return mixed
     */
    public function handle(Request $request, Closure $next)
    {
        $isProduction = app()->environment('production');
        $sessionIsEncrypted = config('artisanpack.security.encrypt');

        if ($isProduction && !$sessionIsEncrypted) {
            throw new RuntimeException(
                'Session encryption is disabled in a production environment. Please enable session encryption for security reasons.'
            );
        }

        return $next($request);
    }
}
