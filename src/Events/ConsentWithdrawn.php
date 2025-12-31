<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Events;

use ArtisanPackUI\Security\Models\ConsentRecord;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

class ConsentWithdrawn
{
    use Dispatchable, SerializesModels;

    public function __construct(public ConsentRecord $consent) {}
}
