<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Services\Csp\Presets;

use ArtisanPackUI\Security\Services\Csp\CspPolicyBuilder;

interface CspPresetInterface
{
    /**
     * Apply the preset to a policy builder.
     */
    public function apply(CspPolicyBuilder $builder, string $nonce): CspPolicyBuilder;

    /**
     * Get the preset name.
     */
    public function getName(): string;

    /**
     * Get the preset description.
     */
    public function getDescription(): string;
}
