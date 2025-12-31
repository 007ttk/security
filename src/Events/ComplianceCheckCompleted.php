<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Events;

use ArtisanPackUI\Security\Models\ComplianceCheckResult;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

class ComplianceCheckCompleted
{
    use Dispatchable, SerializesModels;

    public function __construct(public ComplianceCheckResult $result) {}
}
