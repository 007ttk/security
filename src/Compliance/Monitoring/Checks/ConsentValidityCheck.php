<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Compliance\Monitoring\Checks;

use ArtisanPackUI\Security\Compliance\Monitoring\CheckResult;
use ArtisanPackUI\Security\Models\ConsentPolicy;
use ArtisanPackUI\Security\Models\ConsentRecord;

class ConsentValidityCheck extends BaseComplianceCheck
{
    protected string $name = 'consent_validity';

    protected string $description = 'Validates that all consent records are properly linked to active policies';

    protected string $category = 'consent';

    protected array $regulations = ['gdpr', 'ccpa', 'lgpd'];

    protected string $severity = 'high';

    protected string $remediation = 'Review consent records and ensure all are linked to valid, active consent policies. Request reconsent where necessary.';

    /**
     * Run the check.
     */
    public function run(): CheckResult
    {
        $violations = [];
        $warnings = [];

        // Get all granted consents
        $consents = ConsentRecord::where('status', 'granted')->get();
        $checked = $consents->count();
        $compliant = 0;

        foreach ($consents as $consent) {
            // Check if policy exists and is active
            $policy = ConsentPolicy::find($consent->policy_id);

            if (! $policy) {
                $violations[] = "Consent record {$consent->id} references non-existent policy";

                continue;
            }

            if (! $policy->is_active) {
                $warnings[] = "Consent record {$consent->id} references inactive policy";
            }

            // Check if policy version matches
            $latestPolicy = ConsentPolicy::getLatestForPurpose($consent->purpose);
            if ($latestPolicy && $consent->policy_version !== $latestPolicy->version) {
                $warnings[] = "Consent record {$consent->id} uses outdated policy version {$consent->policy_version}";
            }

            $compliant++;
        }

        if (! empty($violations)) {
            return $this->failed($violations, $checked, $compliant, [
                'warnings' => $warnings,
            ]);
        }

        if (! empty($warnings)) {
            return $this->warning($warnings, $checked, $compliant);
        }

        return $this->passed($checked, $compliant);
    }
}
