<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;

class ConsentPolicy extends Model
{
    /**
     * The table associated with the model.
     */
    protected $table = 'consent_policies';

    /**
     * The attributes that are mass assignable.
     *
     * @var array<string>
     */
    protected $fillable = [
        'purpose',
        'name',
        'description',
        'legal_text',
        'version',
        'previous_version_id',
        'data_categories',
        'processing_details',
        'retention_period',
        'third_party_sharing',
        'rights_description',
        'withdrawal_consequences',
        'is_required',
        'is_active',
        'requires_explicit',
        'minimum_age',
        'effective_at',
        'expires_at',
        'changes_from_previous',
        'created_by',
    ];

    /**
     * The attributes that should be cast.
     *
     * @var array<string, string>
     */
    protected $casts = [
        'data_categories' => 'array',
        'processing_details' => 'array',
        'third_party_sharing' => 'array',
        'changes_from_previous' => 'array',
        'is_required' => 'boolean',
        'is_active' => 'boolean',
        'requires_explicit' => 'boolean',
        'effective_at' => 'datetime',
        'expires_at' => 'datetime',
    ];

    /**
     * Get the previous version of this policy.
     */
    public function previousVersion(): BelongsTo
    {
        return $this->belongsTo(ConsentPolicy::class, 'previous_version_id');
    }

    /**
     * Get consent records for this policy.
     */
    public function consentRecords(): HasMany
    {
        return $this->hasMany(ConsentRecord::class, 'policy_id');
    }

    /**
     * Check if policy is currently effective.
     */
    public function isEffective(): bool
    {
        if (! $this->is_active) {
            return false;
        }

        $now = now();

        if ($this->effective_at && $this->effective_at->isAfter($now)) {
            return false;
        }

        if ($this->expires_at && $this->expires_at->isBefore($now)) {
            return false;
        }

        return true;
    }

    /**
     * Scope for active policies.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<ConsentPolicy>  $query
     * @return \Illuminate\Database\Eloquent\Builder<ConsentPolicy>
     */
    public function scopeActive($query)
    {
        return $query->where('is_active', true);
    }

    /**
     * Scope for effective policies.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<ConsentPolicy>  $query
     * @return \Illuminate\Database\Eloquent\Builder<ConsentPolicy>
     */
    public function scopeEffective($query)
    {
        return $query->where('is_active', true)
            ->where(function ($q) {
                $q->whereNull('effective_at')
                    ->orWhere('effective_at', '<=', now());
            })
            ->where(function ($q) {
                $q->whereNull('expires_at')
                    ->orWhere('expires_at', '>', now());
            });
    }

    /**
     * Get the latest version for a purpose.
     */
    public static function getLatestForPurpose(string $purpose): ?self
    {
        return static::where('purpose', $purpose)
            ->active()
            ->orderByDesc('version')
            ->first();
    }
}
