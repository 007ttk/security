<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Support\Facades\DB;

class ErasureRequest extends Model
{
    /**
     * The table associated with the model.
     */
    protected $table = 'erasure_requests';

    /**
     * The attributes that are mass assignable.
     *
     * @var array<string>
     */
    protected $fillable = [
        'request_number',
        'user_id',
        'requester_type',
        'requester_contact',
        'status',
        'scope',
        'specific_data',
        'reason',
        'identity_verified',
        'identity_verified_at',
        'identity_verified_method',
        'exemptions_found',
        'exemption_explanation',
        'handlers_processed',
        'handlers_failed',
        'third_parties_notified',
        'certificate_path',
        'completed_at',
        'rejected_at',
        'rejected_by',
        'rejection_reason',
        'deadline_at',
        'created_by',
        'processed_by',
    ];

    /**
     * The attributes that should be cast.
     *
     * @var array<string, string>
     */
    protected $casts = [
        'specific_data' => 'array',
        'exemptions_found' => 'array',
        'handlers_processed' => 'array',
        'handlers_failed' => 'array',
        'third_parties_notified' => 'array',
        'identity_verified' => 'boolean',
        'identity_verified_at' => 'datetime',
        'completed_at' => 'datetime',
        'rejected_at' => 'datetime',
        'deadline_at' => 'datetime',
    ];

    /**
     * Boot the model.
     */
    protected static function boot(): void
    {
        parent::boot();

        static::creating(function (ErasureRequest $request) {
            if (empty($request->request_number)) {
                $request->request_number = static::generateRequestNumber();
            }

            if (empty($request->deadline_at)) {
                $days = config('security-compliance.compliance.erasure.deadline_days', 30);
                $request->deadline_at = now()->addDays($days);
            }
        });
    }

    /**
     * Generate a unique request number.
     *
     * Uses a database transaction with pessimistic locking to prevent
     * race conditions when concurrent requests try to generate numbers.
     */
    public static function generateRequestNumber(): string
    {
        return DB::transaction(function () {
            $year = date('Y');

            // Use lockForUpdate to prevent concurrent reads during number generation
            $lastRequest = static::whereYear('created_at', $year)
                ->orderBy('id', 'desc')
                ->lockForUpdate()
                ->first();

            $sequence = $lastRequest
                ? ((int) substr($lastRequest->request_number, -6)) + 1
                : 1;

            return sprintf('ERA-%s-%06d', $year, $sequence);
        });
    }

    /**
     * Get the erasure logs.
     */
    public function logs(): HasMany
    {
        return $this->hasMany(ErasureLog::class, 'request_id');
    }

    /**
     * Check if request is completed.
     */
    public function isCompleted(): bool
    {
        return $this->status === 'completed';
    }

    /**
     * Check if request is rejected.
     */
    public function isRejected(): bool
    {
        return $this->status === 'rejected';
    }

    /**
     * Check if request is pending.
     */
    public function isPending(): bool
    {
        return in_array($this->status, ['pending', 'verifying', 'approved', 'processing']);
    }

    /**
     * Check if deadline has passed.
     */
    public function isOverdue(): bool
    {
        return $this->deadline_at && $this->deadline_at->isPast() && $this->isPending();
    }

    /**
     * Scope for pending requests.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<ErasureRequest>  $query
     * @return \Illuminate\Database\Eloquent\Builder<ErasureRequest>
     */
    public function scopePending($query)
    {
        return $query->whereIn('status', ['pending', 'verifying', 'approved', 'processing']);
    }

    /**
     * Scope for overdue requests.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<ErasureRequest>  $query
     * @return \Illuminate\Database\Eloquent\Builder<ErasureRequest>
     */
    public function scopeOverdue($query)
    {
        return $query->pending()
            ->where('deadline_at', '<', now());
    }
}
