<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Http\Middleware;

use ArtisanPackUI\Security\Authentication\Device\DeviceFingerprintService;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Symfony\Component\HttpFoundation\Response;

class RequireTrustedDevice
{
    /**
     * Create a new middleware instance.
     */
    public function __construct(
        protected DeviceFingerprintService $deviceService
    ) {}

    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        if (! config('security.device_fingerprinting.enabled', true)) {
            return $next($request);
        }

        $user = Auth::user();
        if (! $user) {
            return $next($request);
        }

        // Generate fingerprint
        $fingerprint = $this->deviceService->generateFingerprint($request);

        // Check if device is trusted
        if (! $this->deviceService->isTrustedDevice($user, $fingerprint['hash'])) {
            if ($request->expectsJson()) {
                return response()->json([
                    'error' => 'This action requires a trusted device',
                    'require_trusted_device' => true,
                ], 403);
            }

            return redirect()->back()
                ->with('error', 'This action requires a trusted device. Please trust this device from your security settings first.');
        }

        return $next($request);
    }
}
