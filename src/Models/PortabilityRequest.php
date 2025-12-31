<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Models;

use Illuminate\Database\Eloquent\Model;

class PortabilityRequest extends Model
{
    /**
     * The table associated with the model.
     */
    protected $table = 'portability_requests';

    /**
     * The attributes that are mass assignable.
     *
     * @var array<string>
     */
    protected $fillable = [
        'request_number',
        'user_id',
        'requester_type',
        'status',
        'format',
        'categories',
        'transfer_type',
        'destination_url',
        'destination_verified',
        'file_path',
        'file_size',
        'file_hash',
        'download_count',
        'download_limit',
        'expires_at',
        'completed_at',
        'downloaded_at',
        'deadline_at',
        'created_by',
    ];

    /**
     * The attributes that should be cast.
     *
     * @var array<string, string>
     */
    protected $casts = [
        'categories' => 'array',
        'destination_verified' => 'boolean',
        'expires_at' => 'datetime',
        'completed_at' => 'datetime',
        'downloaded_at' => 'datetime',
        'deadline_at' => 'datetime',
    ];

    /**
     * Boot the model.
     */
    protected static function boot(): void
    {
        parent::boot();

        static::creating(function (PortabilityRequest $request) {
            if (empty($request->request_number)) {
                $request->request_number = static::generateRequestNumber();
            }

            if (empty($request->deadline_at)) {
                $days = config('security-compliance.compliance.portability.deadline_days', 30);
                $request->deadline_at = now()->addDays($days);
            }
        });
    }

    /**
     * Generate a unique request number.
     */
    public static function generateRequestNumber(): string
    {
        $year = date('Y');
        $lastRequest = static::whereYear('created_at', $year)
            ->orderBy('id', 'desc')
            ->lockForUpdate()
            ->first();

        $sequence = $lastRequest
            ? ((int) substr($lastRequest->request_number, -6)) + 1
            : 1;

        return sprintf('POR-%s-%06d', $year, $sequence);
    }

    /**
     * Check if request is completed.
     */
    public function isCompleted(): bool
    {
        return $this->status === 'completed';
    }

    /**
     * Check if export has expired.
     */
    public function isExpired(): bool
    {
        return $this->expires_at && $this->expires_at->isPast();
    }

    /**
     * Check if download limit is reached.
     */
    public function isDownloadLimitReached(): bool
    {
        return $this->download_count >= $this->download_limit;
    }

    /**
     * Check if download is available.
     */
    public function canDownload(): bool
    {
        return $this->isCompleted()
            && ! $this->isExpired()
            && ! $this->isDownloadLimitReached()
            && $this->file_path;
    }

    /**
     * Increment download count.
     */
    public function incrementDownloadCount(): void
    {
        $this->increment('download_count');
        $this->downloaded_at = now();
        $this->save();
    }

    /**
     * Scope for pending requests.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<PortabilityRequest>  $query
     * @return \Illuminate\Database\Eloquent\Builder<PortabilityRequest>
     */
    public function scopePending($query)
    {
        return $query->whereIn('status', ['pending', 'processing']);
    }

    /**
     * Scope for completed requests.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<PortabilityRequest>  $query
     * @return \Illuminate\Database\Eloquent\Builder<PortabilityRequest>
     */
    public function scopeCompleted($query)
    {
        return $query->where('status', 'completed');
    }

    /**
     * Scope for expired requests.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<PortabilityRequest>  $query
     * @return \Illuminate\Database\Eloquent\Builder<PortabilityRequest>
     */
    public function scopeExpired($query)
    {
        return $query->whereNotNull('expires_at')
            ->where('expires_at', '<=', now());
    }
}
