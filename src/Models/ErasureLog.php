<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class ErasureLog extends Model
{
    /**
     * The table associated with the model.
     */
    protected $table = 'erasure_logs';

    /**
     * The attributes that are mass assignable.
     *
     * @var array<string>
     */
    protected $fillable = [
        'request_id',
        'handler_name',
        'action',
        'status',
        'records_found',
        'records_erased',
        'records_retained',
        'retention_reason',
        'backup_reference',
        'error_message',
        'metadata',
        'started_at',
        'completed_at',
    ];

    /**
     * The attributes that should be cast.
     *
     * @var array<string, string>
     */
    protected $casts = [
        'metadata' => 'array',
        'started_at' => 'datetime',
        'completed_at' => 'datetime',
    ];

    /**
     * Get the erasure request.
     */
    public function request(): BelongsTo
    {
        return $this->belongsTo(ErasureRequest::class, 'request_id');
    }

    /**
     * Check if the log indicates success.
     */
    public function isSuccess(): bool
    {
        return $this->status === 'success';
    }

    /**
     * Check if the log indicates failure.
     */
    public function isFailed(): bool
    {
        return $this->status === 'failed';
    }

    /**
     * Get the duration of the operation.
     */
    public function getDurationInSeconds(): ?int
    {
        if (! $this->started_at || ! $this->completed_at) {
            return null;
        }

        return $this->completed_at->diffInSeconds($this->started_at);
    }

    /**
     * Scope for successful logs.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<ErasureLog>  $query
     * @return \Illuminate\Database\Eloquent\Builder<ErasureLog>
     */
    public function scopeSuccessful($query)
    {
        return $query->where('status', 'success');
    }

    /**
     * Scope for failed logs.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<ErasureLog>  $query
     * @return \Illuminate\Database\Eloquent\Builder<ErasureLog>
     */
    public function scopeFailed($query)
    {
        return $query->where('status', 'failed');
    }
}
