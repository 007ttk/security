<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;

class ConsentRecord extends Model
{
    /**
     * The table associated with the model.
     */
    protected $table = 'consent_records';

    /**
     * The attributes that are mass assignable.
     *
     * @var array<string>
     */
    protected $fillable = [
        'user_id',
        'purpose',
        'policy_id',
        'policy_version',
        'status',
        'consent_type',
        'collection_method',
        'collection_context',
        'ip_address',
        'user_agent',
        'proof_reference',
        'granular_choices',
        'expires_at',
        'withdrawn_at',
        'withdrawal_reason',
        'metadata',
    ];

    /**
     * The attributes that should be cast.
     *
     * @var array<string, string>
     */
    protected $casts = [
        'collection_context' => 'array',
        'granular_choices' => 'array',
        'metadata' => 'array',
        'expires_at' => 'datetime',
        'withdrawn_at' => 'datetime',
    ];

    /**
     * Get the consent policy.
     */
    public function policy(): BelongsTo
    {
        return $this->belongsTo(ConsentPolicy::class, 'policy_id');
    }

    /**
     * Get the audit logs for this consent.
     */
    public function auditLogs(): HasMany
    {
        return $this->hasMany(ConsentAuditLog::class, 'consent_record_id');
    }

    /**
     * Check if consent is currently valid.
     */
    public function isValid(): bool
    {
        if ($this->status !== 'granted') {
            return false;
        }

        if ($this->expires_at && $this->expires_at->isPast()) {
            return false;
        }

        return true;
    }

    /**
     * Check if consent has expired.
     */
    public function isExpired(): bool
    {
        return $this->expires_at && $this->expires_at->isPast();
    }

    /**
     * Check if consent was withdrawn.
     */
    public function isWithdrawn(): bool
    {
        return $this->status === 'withdrawn';
    }

    /**
     * Scope for granted consents.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<ConsentRecord>  $query
     * @return \Illuminate\Database\Eloquent\Builder<ConsentRecord>
     */
    public function scopeGranted($query)
    {
        return $query->where('status', 'granted');
    }

    /**
     * Scope for valid (non-expired, granted) consents.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<ConsentRecord>  $query
     * @return \Illuminate\Database\Eloquent\Builder<ConsentRecord>
     */
    public function scopeValid($query)
    {
        return $query->where('status', 'granted')
            ->where(function ($q) {
                $q->whereNull('expires_at')
                    ->orWhere('expires_at', '>', now());
            });
    }

    /**
     * Scope for expired consents.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<ConsentRecord>  $query
     * @return \Illuminate\Database\Eloquent\Builder<ConsentRecord>
     */
    public function scopeExpired($query)
    {
        return $query->whereNotNull('expires_at')
            ->where('expires_at', '<=', now());
    }
}
