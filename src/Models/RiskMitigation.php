<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class RiskMitigation extends Model
{
    /**
     * The table associated with the model.
     */
    protected $table = 'risk_mitigations';

    /**
     * The attributes that are mass assignable.
     *
     * @var array<string>
     */
    protected $fillable = [
        'risk_id',
        'title',
        'description',
        'type',
        'status',
        'priority',
        'assigned_to',
        'due_date',
        'implemented_at',
        'verified_at',
        'verified_by',
        'effectiveness_rating',
        'notes',
    ];

    /**
     * The attributes that should be cast.
     *
     * @var array<string, string>
     */
    protected $casts = [
        'due_date' => 'date',
        'implemented_at' => 'datetime',
        'verified_at' => 'datetime',
    ];

    /**
     * Get the risk this mitigation is for.
     */
    public function risk(): BelongsTo
    {
        return $this->belongsTo(AssessmentRisk::class, 'risk_id');
    }

    /**
     * Check if mitigation is implemented.
     */
    public function isImplemented(): bool
    {
        return in_array($this->status, ['implemented', 'verified']);
    }

    /**
     * Check if mitigation is verified.
     */
    public function isVerified(): bool
    {
        return $this->status === 'verified';
    }

    /**
     * Check if mitigation is overdue.
     */
    public function isOverdue(): bool
    {
        return $this->due_date && $this->due_date->isPast() && ! $this->isImplemented();
    }

    /**
     * Scope for pending mitigations.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<RiskMitigation>  $query
     * @return \Illuminate\Database\Eloquent\Builder<RiskMitigation>
     */
    public function scopePending($query)
    {
        return $query->whereIn('status', ['planned', 'in_progress']);
    }

    /**
     * Scope for overdue mitigations.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<RiskMitigation>  $query
     * @return \Illuminate\Database\Eloquent\Builder<RiskMitigation>
     */
    public function scopeOverdue($query)
    {
        return $query->whereNotIn('status', ['implemented', 'verified'])
            ->whereNotNull('due_date')
            ->where('due_date', '<', now());
    }
}
