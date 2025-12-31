<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;

class AssessmentRisk extends Model
{
    /**
     * The table associated with the model.
     */
    protected $table = 'assessment_risks';

    /**
     * The attributes that are mass assignable.
     *
     * @var array<string>
     */
    protected $fillable = [
        'assessment_id',
        'risk_category',
        'risk_title',
        'risk_description',
        'likelihood',
        'impact',
        'inherent_score',
        'residual_score',
        'risk_level',
        'risk_owner',
        'status',
        'accepted_by',
        'accepted_at',
        'acceptance_justification',
    ];

    /**
     * The attributes that should be cast.
     *
     * @var array<string, string>
     */
    protected $casts = [
        'inherent_score' => 'decimal:2',
        'residual_score' => 'decimal:2',
        'accepted_at' => 'datetime',
    ];

    /**
     * Likelihood values and their numeric scores.
     *
     * @var array<string, int>
     */
    public const LIKELIHOOD_SCORES = [
        'rare' => 1,
        'unlikely' => 2,
        'possible' => 3,
        'likely' => 4,
        'almost_certain' => 5,
    ];

    /**
     * Impact values and their numeric scores.
     *
     * @var array<string, int>
     */
    public const IMPACT_SCORES = [
        'negligible' => 1,
        'minor' => 2,
        'moderate' => 3,
        'major' => 4,
        'severe' => 5,
    ];

    /**
     * Get the assessment.
     */
    public function assessment(): BelongsTo
    {
        return $this->belongsTo(DataProtectionAssessment::class, 'assessment_id');
    }

    /**
     * Get the mitigations for this risk.
     */
    public function mitigations(): HasMany
    {
        return $this->hasMany(RiskMitigation::class, 'risk_id');
    }

    /**
     * Calculate the inherent risk score.
     */
    public function calculateInherentScore(): float
    {
        $likelihood = self::LIKELIHOOD_SCORES[$this->likelihood] ?? 1;
        $impact = self::IMPACT_SCORES[$this->impact] ?? 1;

        return $likelihood * $impact;
    }

    /**
     * Determine risk level based on score.
     */
    public static function determineRiskLevel(float $score): string
    {
        if ($score <= 4) {
            return 'low';
        }
        if ($score <= 9) {
            return 'medium';
        }
        if ($score <= 16) {
            return 'high';
        }

        return 'critical';
    }

    /**
     * Check if risk is mitigated.
     */
    public function isMitigated(): bool
    {
        return $this->status === 'mitigated';
    }

    /**
     * Check if risk is accepted.
     */
    public function isAccepted(): bool
    {
        return $this->status === 'accepted';
    }

    /**
     * Scope for high-level risks.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<AssessmentRisk>  $query
     * @return \Illuminate\Database\Eloquent\Builder<AssessmentRisk>
     */
    public function scopeHighRisk($query)
    {
        return $query->whereIn('risk_level', ['high', 'critical']);
    }
}
