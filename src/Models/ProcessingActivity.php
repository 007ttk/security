<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;

class ProcessingActivity extends Model
{
    /**
     * The table associated with the model.
     */
    protected $table = 'processing_activities';

    /**
     * The attributes that are mass assignable.
     *
     * @var array<string>
     */
    protected $fillable = [
        'name',
        'description',
        'controller_name',
        'controller_contact',
        'processor_name',
        'processor_contact',
        'dpo_contact',
        'purposes',
        'legal_bases',
        'data_categories',
        'data_subjects',
        'recipients',
        'third_countries',
        'safeguards',
        'retention_policy',
        'security_measures',
        'automated_decisions',
        'dpia_required',
        'dpia_reference',
        'status',
        'suspension_reason',
        'suspended_at',
        'last_review_at',
        'next_review_at',
    ];

    /**
     * The attributes that should be cast.
     *
     * @var array<string, string>
     */
    protected $casts = [
        'purposes' => 'array',
        'legal_bases' => 'array',
        'data_categories' => 'array',
        'data_subjects' => 'array',
        'recipients' => 'array',
        'third_countries' => 'array',
        'safeguards' => 'array',
        'retention_policy' => 'array',
        'security_measures' => 'array',
        'automated_decisions' => 'array',
        'dpia_required' => 'boolean',
        'suspended_at' => 'datetime',
        'last_review_at' => 'datetime',
        'next_review_at' => 'datetime',
    ];

    /**
     * Get the assessments for this processing activity.
     */
    public function assessments(): HasMany
    {
        return $this->hasMany(DataProtectionAssessment::class, 'processing_activity_id');
    }

    /**
     * Check if this activity is active.
     */
    public function isActive(): bool
    {
        return $this->status === 'active';
    }

    /**
     * Check if review is due.
     */
    public function isReviewDue(): bool
    {
        return $this->next_review_at && $this->next_review_at->isPast();
    }

    /**
     * Scope for active activities.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<ProcessingActivity>  $query
     * @return \Illuminate\Database\Eloquent\Builder<ProcessingActivity>
     */
    public function scopeActive($query)
    {
        return $query->where('status', 'active');
    }

    /**
     * Scope for activities requiring DPIA.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<ProcessingActivity>  $query
     * @return \Illuminate\Database\Eloquent\Builder<ProcessingActivity>
     */
    public function scopeRequiresDpia($query)
    {
        return $query->where('dpia_required', true);
    }
}
