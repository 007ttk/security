<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Events;

use ArtisanPackUI\Security\Models\PortabilityRequest;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

class DataExportRequested
{
    use Dispatchable, SerializesModels;

    public function __construct(public PortabilityRequest $request) {}
}
