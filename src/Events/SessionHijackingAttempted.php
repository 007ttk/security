<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Events;

use ArtisanPackUI\Security\Models\UserSession;
use Illuminate\Broadcasting\InteractsWithSockets;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Http\Request;
use Illuminate\Queue\SerializesModels;

class SessionHijackingAttempted
{
    use Dispatchable;
    use InteractsWithSockets;
    use SerializesModels;

    /**
     * Create a new event instance.
     *
     * @param  array<string>  $violations
     */
    public function __construct(
        public mixed $user,
        public UserSession $session,
        public Request $request,
        public array $violations = []
    ) {}

    /**
     * Get a summary of the violations.
     */
    public function getViolationsSummary(): string
    {
        return implode(', ', $this->violations);
    }
}
