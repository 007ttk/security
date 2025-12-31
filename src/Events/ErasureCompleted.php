<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Events;

use ArtisanPackUI\Security\Models\ErasureRequest;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

class ErasureCompleted
{
    use Dispatchable, SerializesModels;

    public function __construct(public ErasureRequest $request) {}
}
