<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Events;

use ArtisanPackUI\Security\Authentication\Sso\SsoUser;
use ArtisanPackUI\Security\Models\SsoConfiguration;
use ArtisanPackUI\Security\Models\SsoIdentity;
use Illuminate\Broadcasting\InteractsWithSockets;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

class SsoLoginSucceeded
{
    use Dispatchable;
    use InteractsWithSockets;
    use SerializesModels;

    /**
     * Create a new event instance.
     */
    public function __construct(
        public mixed $user,
        public SsoIdentity $ssoIdentity,
        public SsoUser $ssoUser,
        public SsoConfiguration $configuration,
        public bool $isNewUser = false
    ) {}
}
