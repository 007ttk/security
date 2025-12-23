<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Events;

use Illuminate\Broadcasting\InteractsWithSockets;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

class CspPolicyApplied
{
    use Dispatchable, InteractsWithSockets, SerializesModels;

    /**
     * Create a new event instance.
     */
    public function __construct(
        public readonly string $policy,
        public readonly string $nonce,
    ) {}
}
