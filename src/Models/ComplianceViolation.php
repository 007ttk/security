<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Models;

use Illuminate\Database\Eloquent\Model;

class ComplianceViolation extends Model
{
    /**
     * The table associated with the model.
     */
    protected $table = 'compliance_violations';

    /**
     * The attributes that are mass assignable.
     *
     * @var array<string>
     */
    protected $fillable = [
        'violation_number',
        'check_name',
        'category',
        'regulation',
        'article_reference',
        'severity',
        'title',
        'description',
        'affected_records',
        'affected_count',
        'evidence',
        'remediation_steps',
        'remediation_deadline',
        'status',
        'assigned_to',
        'acknowledged_at',
        'acknowledged_by',
        'resolved_at',
        'resolved_by',
        'resolution_notes',
        'accepted_risk',
        'risk_acceptance_by',
        'risk_acceptance_reason',
    ];

    /**
     * The attributes that should be cast.
     *
     * @var array<string, string>
     */
    protected $casts = [
        'affected_records' => 'array',
        'evidence' => 'array',
        'remediation_steps' => 'array',
        'remediation_deadline' => 'datetime',
        'acknowledged_at' => 'datetime',
        'resolved_at' => 'datetime',
        'accepted_risk' => 'boolean',
    ];

    /**
     * Boot the model.
     */
    protected static function boot(): void
    {
        parent::boot();

        static::creating(function (ComplianceViolation $violation) {
            if (empty($violation->violation_number)) {
                $violation->violation_number = static::generateViolationNumber();
            }
        });
    }

    /**
     * Generate a unique violation number.
     */
    public static function generateViolationNumber(): string
    {
        $year = date('Y');
        
        return \DB::transaction(function () use ($year) {
            $lastViolation = static::whereYear('created_at', $year)
                ->orderBy('id', 'desc')
                ->lockForUpdate()
                ->first();

            $sequence = $lastViolation
                ? ((int) substr($lastViolation->violation_number, -6)) + 1
                : 1;

            return sprintf('VIO-%s-%06d', $year, $sequence);
        });
    }

    /**
     * Check if violation is open.
     */
    public function isOpen(): bool
    {
        return in_array($this->status, ['open', 'acknowledged', 'in_progress']);
    }

    /**
     * Check if violation is resolved.
     */
    public function isResolved(): bool
    {
        return $this->status === 'resolved';
    }

    /**
     * Check if remediation is overdue.
     */
    public function isOverdue(): bool
    {
        return $this->remediation_deadline
            && $this->remediation_deadline->isPast()
            && $this->isOpen();
    }

    /**
     * Check if this is a critical violation.
     */
    public function isCritical(): bool
    {
        return $this->severity === 'critical';
    }

    /**
     * Scope for open violations.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<ComplianceViolation>  $query
     * @return \Illuminate\Database\Eloquent\Builder<ComplianceViolation>
     */
    public function scopeOpen($query)
    {
        return $query->whereIn('status', ['open', 'acknowledged', 'in_progress']);
    }

    /**
     * Scope for severity level.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<ComplianceViolation>  $query
     * @return \Illuminate\Database\Eloquent\Builder<ComplianceViolation>
     */
    public function scopeBySeverity($query, string $severity)
    {
        return $query->where('severity', $severity);
    }

    /**
     * Scope for overdue violations.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<ComplianceViolation>  $query
     * @return \Illuminate\Database\Eloquent\Builder<ComplianceViolation>
     */
    public function scopeOverdue($query)
    {
        return $query->open()
            ->whereNotNull('remediation_deadline')
            ->where('remediation_deadline', '<', now());
    }
}
