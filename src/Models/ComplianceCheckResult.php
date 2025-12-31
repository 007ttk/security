<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Models;

use Illuminate\Database\Eloquent\Model;

class ComplianceCheckResult extends Model
{
    /**
     * The table associated with the model.
     */
    protected $table = 'compliance_check_results';

    /**
     * The attributes that are mass assignable.
     *
     * @var array<string>
     */
    protected $fillable = [
        'check_name',
        'status',
        'score',
        'violations_found',
        'warnings_found',
        'items_checked',
        'items_compliant',
        'details',
        'execution_time_ms',
        'next_run_at',
        'metadata',
    ];

    /**
     * The attributes that should be cast.
     *
     * @var array<string, string>
     */
    protected $casts = [
        'score' => 'decimal:2',
        'details' => 'array',
        'metadata' => 'array',
        'next_run_at' => 'datetime',
    ];

    /**
     * Check if the result indicates a pass.
     */
    public function isPassed(): bool
    {
        return $this->status === 'passed';
    }

    /**
     * Check if the result indicates a failure.
     */
    public function isFailed(): bool
    {
        return $this->status === 'failed';
    }

    /**
     * Check if the result indicates a warning.
     */
    public function isWarning(): bool
    {
        return $this->status === 'warning';
    }

    /**
     * Get the compliance percentage.
     */
    public function getCompliancePercentage(): float
    {
        if ($this->items_checked === 0) {
            return 100.0;
        }

        return ($this->items_compliant / $this->items_checked) * 100;
    }

    /**
     * Scope for a specific check.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<ComplianceCheckResult>  $query
     * @return \Illuminate\Database\Eloquent\Builder<ComplianceCheckResult>
     */
    public function scopeForCheck($query, string $checkName)
    {
        return $query->where('check_name', $checkName);
    }

    /**
     * Scope for passed results.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<ComplianceCheckResult>  $query
     * @return \Illuminate\Database\Eloquent\Builder<ComplianceCheckResult>
     */
    public function scopePassed($query)
    {
        return $query->where('status', 'passed');
    }

    /**
     * Scope for failed results.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<ComplianceCheckResult>  $query
     * @return \Illuminate\Database\Eloquent\Builder<ComplianceCheckResult>
     */
    public function scopeFailed($query)
    {
        return $query->where('status', 'failed');
    }

    /**
     * Get the latest result for a check.
     */
    public static function getLatestForCheck(string $checkName): ?self
    {
        return static::forCheck($checkName)
            ->orderByDesc('created_at')
            ->first();
    }
}
