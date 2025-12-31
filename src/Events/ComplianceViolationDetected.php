<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Events;

use ArtisanPackUI\Security\Models\ComplianceViolation;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

class ComplianceViolationDetected
{
    use Dispatchable, SerializesModels;

    public function __construct(public ComplianceViolation $violation) {}
}
