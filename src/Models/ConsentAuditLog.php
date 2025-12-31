<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class ConsentAuditLog extends Model
{
    /**
     * The table associated with the model.
     */
    protected $table = 'consent_audit_logs';

    /**
     * The attributes that are mass assignable.
     *
     * @var array<string>
     */
    protected $fillable = [
        'consent_record_id',
        'user_id',
        'action',
        'purpose',
        'old_status',
        'new_status',
        'policy_version',
        'actor_type',
        'actor_id',
        'reason',
        'ip_address',
        'user_agent',
        'metadata',
    ];

    /**
     * The attributes that should be cast.
     *
     * @var array<string, string>
     */
    protected $casts = [
        'metadata' => 'array',
    ];

    /**
     * Get the consent record.
     */
    public function consentRecord(): BelongsTo
    {
        return $this->belongsTo(ConsentRecord::class, 'consent_record_id');
    }

    /**
     * Scope for a specific user.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<ConsentAuditLog>  $query
     * @return \Illuminate\Database\Eloquent\Builder<ConsentAuditLog>
     */
    public function scopeForUser($query, int $userId)
    {
        return $query->where('user_id', $userId);
    }

    /**
     * Scope for a specific purpose.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<ConsentAuditLog>  $query
     * @return \Illuminate\Database\Eloquent\Builder<ConsentAuditLog>
     */
    public function scopeForPurpose($query, string $purpose)
    {
        return $query->where('purpose', $purpose);
    }

    /**
     * Scope for a specific action.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<ConsentAuditLog>  $query
     * @return \Illuminate\Database\Eloquent\Builder<ConsentAuditLog>
     */
    public function scopeForAction($query, string $action)
    {
        return $query->where('action', $action);
    }
}
