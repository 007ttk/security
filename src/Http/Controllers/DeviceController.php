<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Http\Controllers;

use ArtisanPackUI\Security\Authentication\Device\DeviceFingerprintService;
use ArtisanPackUI\Security\Events\DeviceRevoked;
use ArtisanPackUI\Security\Events\DeviceTrusted;
use ArtisanPackUI\Security\Models\UserDevice;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Auth;

class DeviceController extends Controller
{
    /**
     * Create a new controller instance.
     */
    public function __construct(
        protected DeviceFingerprintService $deviceService
    ) {}

    /**
     * List all devices for the current user.
     */
    public function index(): JsonResponse
    {
        $user = Auth::user();
        if (! $user) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        $devices = $this->deviceService->getUserDevices($user);

        $data = $devices->map(function (UserDevice $device) {
            return [
                'id' => $device->id,
                'name' => $device->getDisplayName(),
                'type' => $device->type,
                'browser' => $device->browser,
                'browser_version' => $device->browser_version,
                'os' => $device->os,
                'os_version' => $device->os_version,
                'is_trusted' => $device->isTrusted(),
                'trusted_at' => $device->trusted_at,
                'trust_expires_at' => $device->trust_expires_at,
                'last_ip_address' => $device->last_ip_address,
                'last_location' => $device->last_location,
                'last_used_at' => $device->last_used_at,
                'login_count' => $device->login_count,
                'created_at' => $device->created_at,
            ];
        });

        return response()->json(['devices' => $data]);
    }

    /**
     * Get the current device.
     */
    public function current(Request $request): JsonResponse
    {
        $user = Auth::user();
        if (! $user) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        $fingerprint = $this->deviceService->generateFingerprint($request);
        $device = $user->getDevice($fingerprint['hash']);

        if (! $device) {
            return response()->json(['error' => 'Device not found'], 404);
        }

        return response()->json([
            'device' => [
                'id' => $device->id,
                'name' => $device->getDisplayName(),
                'type' => $device->type,
                'is_trusted' => $device->isTrusted(),
                'trust_score' => $this->deviceService->calculateTrustScore($device),
                'fingerprint_hash' => $device->fingerprint_hash,
            ],
        ]);
    }

    /**
     * Update a device.
     */
    public function update(Request $request, int $device): JsonResponse
    {
        $user = Auth::user();
        if (! $user) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        $validated = $request->validate([
            'name' => 'required|string|max:255',
        ]);

        $deviceModel = UserDevice::where('user_id', $user->getAuthIdentifier())
            ->where('id', $device)
            ->first();

        if (! $deviceModel) {
            return response()->json(['error' => 'Device not found'], 404);
        }

        $deviceModel->name = $validated['name'];
        $deviceModel->save();

        return response()->json(['success' => true, 'message' => 'Device updated']);
    }

    /**
     * Trust a device.
     */
    public function trust(Request $request, int $device): JsonResponse
    {
        $user = Auth::user();
        if (! $user) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        $deviceModel = UserDevice::where('user_id', $user->getAuthIdentifier())
            ->where('id', $device)
            ->first();

        if (! $deviceModel) {
            return response()->json(['error' => 'Device not found'], 404);
        }

        $validated = $request->validate([
            'expiration_days' => 'nullable|integer|min:1|max:365',
        ]);

        $expirationDays = $validated['expiration_days'] ?? null;
        $this->deviceService->trustDevice($deviceModel, $expirationDays);

        event(new DeviceTrusted($user, $deviceModel));

        return response()->json(['success' => true, 'message' => 'Device trusted']);
    }

    /**
     * Revoke trust from a device.
     */
    public function revoke(int $device): JsonResponse
    {
        $user = Auth::user();
        if (! $user) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        $deviceModel = UserDevice::where('user_id', $user->getAuthIdentifier())
            ->where('id', $device)
            ->first();

        if (! $deviceModel) {
            return response()->json(['error' => 'Device not found'], 404);
        }

        event(new DeviceRevoked($user, $deviceModel));

        $this->deviceService->deleteDevice($deviceModel);

        return response()->json(['success' => true, 'message' => 'Device removed']);
    }
}
