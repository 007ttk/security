<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Events;

use ArtisanPackUI\Security\Models\WebAuthnCredential;
use Illuminate\Broadcasting\InteractsWithSockets;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Http\Request;
use Illuminate\Queue\SerializesModels;

class WebAuthnRegistered
{
    use Dispatchable;
    use InteractsWithSockets;
    use SerializesModels;

    /**
     * Create a new event instance.
     */
    public function __construct(
        public mixed $user,
        public WebAuthnCredential $credential,
        public Request $request
    ) {}
}
