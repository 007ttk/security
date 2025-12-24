<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Console\Commands;

use ArtisanPackUI\Security\Models\SuspiciousActivity;
use Illuminate\Console\Command;

class PruneSuspiciousActivity extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'security:suspicious-activity:prune
                            {--days=90 : Delete records older than this many days}
                            {--keep-critical : Keep critical severity records}
                            {--dry-run : Show what would be deleted without actually deleting}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Prune old suspicious activity records';

    /**
     * Execute the console command.
     */
    public function handle(): int
    {
        $days = (int) $this->option('days');
        $keepCritical = $this->option('keep-critical');
        $dryRun = $this->option('dry-run');

        $this->info("Pruning suspicious activity records older than {$days} days...");

        $query = SuspiciousActivity::where('created_at', '<', now()->subDays($days));

        if ($keepCritical) {
            $query->where('severity', '!=', SuspiciousActivity::SEVERITY_CRITICAL);
            $this->line('Keeping critical severity records');
        }

        $count = $query->count();
        $this->line("Found {$count} records to delete");

        if ($dryRun) {
            $this->warn('Dry run mode - no records were deleted');

            // Show breakdown by severity
            $breakdown = SuspiciousActivity::where('created_at', '<', now()->subDays($days))
                ->when($keepCritical, fn ($q) => $q->where('severity', '!=', SuspiciousActivity::SEVERITY_CRITICAL))
                ->selectRaw('severity, count(*) as count')
                ->groupBy('severity')
                ->pluck('count', 'severity');

            if ($breakdown->isNotEmpty()) {
                $this->table(['Severity', 'Count'], $breakdown->map(fn ($count, $severity) => [$severity, $count])->values());
            }

            return self::SUCCESS;
        }

        $deleted = $query->delete();
        $this->info("Deleted {$deleted} suspicious activity record(s)");

        return self::SUCCESS;
    }
}
