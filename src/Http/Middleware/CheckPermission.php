<?php

namespace ArtisanPackUI\Security\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class CheckPermission
{
    public function handle(Request $request, Closure $next, $permission)
    {
        if (Auth::guest()) {
            abort(401);
        }

        if (!Auth::user()->can($permission)) {
            abort(403);
        }

        return $next($request);
    }
}
