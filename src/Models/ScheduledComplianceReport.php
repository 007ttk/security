<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Models;

use Cron\CronExpression;
use Illuminate\Database\Eloquent\Model;

class ScheduledComplianceReport extends Model
{
    /**
     * The table associated with the model.
     */
    protected $table = 'scheduled_compliance_reports';

    /**
     * The attributes that are mass assignable.
     *
     * @var array<string>
     */
    protected $fillable = [
        'report_type',
        'name',
        'cron_expression',
        'recipients',
        'options',
        'format',
        'is_active',
        'last_run_at',
        'next_run_at',
    ];

    /**
     * The attributes that should be cast.
     *
     * @var array<string, string>
     */
    protected $casts = [
        'recipients' => 'array',
        'options' => 'array',
        'is_active' => 'boolean',
        'last_run_at' => 'datetime',
        'next_run_at' => 'datetime',
    ];

    /**
     * Boot the model.
     */
    protected static function boot(): void
    {
        parent::boot();

        static::creating(function (ScheduledComplianceReport $report) {
            if (empty($report->next_run_at)) {
                $report->next_run_at = $report->calculateNextRun();
            }
        });

        static::updating(function (ScheduledComplianceReport $report) {
            if ($report->isDirty('cron_expression')) {
                $report->next_run_at = $report->calculateNextRun();
            }
        });
    }

    /**
     * Calculate the next run time based on cron expression.
     */
    public function calculateNextRun(): \DateTime
    {
        try {
            $cron = new CronExpression($this->cron_expression);
            return $cron->getNextRunDate();
        } catch (\InvalidArgumentException $e) {
            // Return a far-future date for invalid expressions
            // Consider logging or validating at input time instead
            return new \DateTime('+100 years');
        }
    }

    /**
     * Check if the report is due to run.
     */
    public function isDue(): bool
    {
        if (! $this->is_active) {
            return false;
        }

        return $this->next_run_at && $this->next_run_at->isPast();
    }

    /**
     * Mark the report as run and schedule next run.
     */
    public function markAsRun(): void
    {
        $this->last_run_at = now();
        $this->next_run_at = $this->calculateNextRun();
        $this->save();
    }

    /**
     * Scope for active reports.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<ScheduledComplianceReport>  $query
     * @return \Illuminate\Database\Eloquent\Builder<ScheduledComplianceReport>
     */
    public function scopeActive($query)
    {
        return $query->where('is_active', true);
    }

    /**
     * Scope for due reports.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<ScheduledComplianceReport>  $query
     * @return \Illuminate\Database\Eloquent\Builder<ScheduledComplianceReport>
     */
    public function scopeDue($query)
    {
        return $query->active()
            ->whereNotNull('next_run_at')
            ->where('next_run_at', '<=', now());
    }
}
