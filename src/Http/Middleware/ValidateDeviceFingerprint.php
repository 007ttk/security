<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Http\Middleware;

use ArtisanPackUI\Security\Authentication\Device\DeviceFingerprintService;
use ArtisanPackUI\Security\Events\NewDeviceLogin;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Symfony\Component\HttpFoundation\Response;

class ValidateDeviceFingerprint
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

        // Check if device is recognized
        $isRecognized = $this->deviceService->isRecognizedDevice($user, $fingerprint['hash']);

        if (! $isRecognized) {
            // New device - create and track it
            $device = $this->deviceService->findOrCreateDevice(
                $user,
                $fingerprint['hash'],
                $fingerprint['components']
            );

            // Record the login
            $this->deviceService->recordDeviceLogin($device, $request);

            // Fire event for new device
            event(new NewDeviceDetected($user, $device, $request));

            // Store in session for current request
            session(['current_device_id' => $device->id]);
        } else {
            // Existing device - update last used
            $device = $user->getDevice($fingerprint['hash']);

            if ($device) {
                $this->deviceService->recordDeviceLogin($device, $request);
                session(['current_device_id' => $device->id]);

                // Check for auto-trust
                if ($this->deviceService->shouldAutoTrust($device)) {
                    $this->deviceService->trustDevice($device);
                }
            }
        }

        return $next($request);
    }
}
