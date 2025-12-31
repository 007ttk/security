<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;

class DataProtectionAssessment extends Model
{
    /**
     * The table associated with the model.
     */
    protected $table = 'data_protection_assessments';

    /**
     * The attributes that are mass assignable.
     *
     * @var array<string>
     */
    protected $fillable = [
        'assessment_number',
        'title',
        'description',
        'processing_activity_id',
        'status',
        'version',
        'parent_assessment_id',
        'data_categories',
        'data_subjects',
        'processing_purposes',
        'legal_bases',
        'recipients',
        'retention_periods',
        'transfers',
        'security_measures',
        'overall_risk_score',
        'overall_risk_level',
        'dpo_opinion',
        'dpo_reviewed_at',
        'dpo_reviewed_by',
        'created_by',
        'reviewed_by',
        'approved_at',
        'next_review_at',
    ];

    /**
     * The attributes that should be cast.
     *
     * @var array<string, string>
     */
    protected $casts = [
        'data_categories' => 'array',
        'data_subjects' => 'array',
        'processing_purposes' => 'array',
        'legal_bases' => 'array',
        'recipients' => 'array',
        'retention_periods' => 'array',
        'transfers' => 'array',
        'security_measures' => 'array',
        'overall_risk_score' => 'decimal:2',
        'approved_at' => 'datetime',
        'next_review_at' => 'datetime',
        'dpo_reviewed_at' => 'datetime',
    ];

    /**
     * Boot the model.
     */
    protected static function boot(): void
    {
        parent::boot();

        static::creating(function (DataProtectionAssessment $assessment) {
            if (empty($assessment->assessment_number)) {
                $assessment->assessment_number = static::generateAssessmentNumber();
            }
        });
    }

    /**
     * Generate a unique assessment number.
     */
    public static function generateAssessmentNumber(): string
    {
        $year = date('Y');
        $sequence = DB::transaction(function () use ($year) {
            $lastAssessment = static::whereYear('created_at', $year)
                ->orderBy('id', 'desc')
                ->lockForUpdate()
                ->first();

            return $lastAssessment
                ? ((int) substr($lastAssessment->assessment_number, -6)) + 1
                : 1;
        });

        return sprintf('DPIA-%s-%06d', $year, $sequence);
    }

    /**
     * Get the processing activity.
     */
    public function processingActivity(): BelongsTo
    {
        return $this->belongsTo(ProcessingActivity::class, 'processing_activity_id');
    }

    /**
     * Get the parent assessment (for revisions).
     */
    public function parentAssessment(): BelongsTo
    {
        return $this->belongsTo(DataProtectionAssessment::class, 'parent_assessment_id');
    }

    /**
     * Get child assessments (revisions).
     */
    public function revisions(): HasMany
    {
        return $this->hasMany(DataProtectionAssessment::class, 'parent_assessment_id');
    }

    /**
     * Get the risks for this assessment.
     */
    public function risks(): HasMany
    {
        return $this->hasMany(AssessmentRisk::class, 'assessment_id');
    }

    /**
     * Check if assessment is approved.
     */
    public function isApproved(): bool
    {
        return $this->status === 'approved';
    }

    /**
     * Check if assessment is in draft status.
     */
    public function isDraft(): bool
    {
        return $this->status === 'draft';
    }

    /**
     * Scope for approved assessments.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<DataProtectionAssessment>  $query
     * @return \Illuminate\Database\Eloquent\Builder<DataProtectionAssessment>
     */
    public function scopeApproved($query)
    {
        return $query->where('status', 'approved');
    }

    /**
     * Scope for high risk assessments.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<DataProtectionAssessment>  $query
     * @return \Illuminate\Database\Eloquent\Builder<DataProtectionAssessment>
     */
    public function scopeHighRisk($query)
    {
        return $query->whereIn('overall_risk_level', ['high', 'critical']);
    }
}
