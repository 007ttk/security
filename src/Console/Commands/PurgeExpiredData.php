<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Console\Commands;

use ArtisanPackUI\Security\Compliance\Minimization\DataMinimizerService;
use ArtisanPackUI\Security\Models\RetentionPolicy;
use Illuminate\Console\Command;

class PurgeExpiredData extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'compliance:purge-expired
                            {--dry-run : Show what would be purged without actually purging}
                            {--policy= : Only purge for a specific policy}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Purge data that has exceeded retention periods';

    public function __construct(protected DataMinimizerService $minimizer)
    {
        parent::__construct();
    }

    /**
     * Execute the console command.
     */
    public function handle(): int
    {
        $dryRun = $this->option('dry-run');
        $policyName = $this->option('policy');

        if ($dryRun) {
            $this->warn('Running in dry-run mode - no data will be deleted');
        }

        $policies = RetentionPolicy::active();

        if ($policyName) {
            $policies = $policies->where('name', $policyName);
        }

        $policies = $policies->get();

        if ($policies->isEmpty()) {
            $this->info('No active retention policies found');

            return 0;
        }

        $totalPurged = 0;

        foreach ($policies as $policy) {
            if (! $policy->model_class || ! class_exists($policy->model_class)) {
                $this->warn("Skipping policy '{$policy->name}' - invalid model class");

                continue;
            }

            $this->line("Processing policy: {$policy->name}");

            $expired = $this->minimizer->getExpiredData($policy->model_class);
            $count = $expired->count();

            if ($count === 0) {
                $this->info("  No expired data found");

                continue;
            }

            if ($dryRun) {
                $this->info("  Would purge {$count} record(s)");
            } else {
                $purged = $this->minimizer->purgeExpiredData($policy->model_class);
                $this->info("  Purged {$purged} record(s)");
                $totalPurged += $purged;
            }
        }

        $this->newLine();

        if ($dryRun) {
            $this->info('Dry run complete. Run without --dry-run to actually purge data.');
        } else {
            $this->info("Total records purged: {$totalPurged}");
        }

        return 0;
    }
}
