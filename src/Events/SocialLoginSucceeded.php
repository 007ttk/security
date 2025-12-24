<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Events;

use ArtisanPackUI\Security\Authentication\Social\SocialUser;
use ArtisanPackUI\Security\Models\SocialIdentity;
use Illuminate\Broadcasting\InteractsWithSockets;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

class SocialLoginSucceeded
{
    use Dispatchable;
    use InteractsWithSockets;
    use SerializesModels;

    /**
     * Create a new event instance.
     */
    public function __construct(
        public mixed $user,
        public SocialIdentity $socialIdentity,
        public SocialUser $socialUser,
        public string $provider,
        public bool $isNewUser = false
    ) {}
}
