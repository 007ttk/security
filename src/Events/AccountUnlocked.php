<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Events;

use ArtisanPackUI\Security\Models\AccountLockout;
use Illuminate\Broadcasting\InteractsWithSockets;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

class AccountUnlocked
{
    use Dispatchable;
    use InteractsWithSockets;
    use SerializesModels;

    /**
     * Create a new event instance.
     */
    public function __construct(
        public AccountLockout $lockout,
        public mixed $user = null,
        public string $unlockedBy = 'system'
    ) {}
}
