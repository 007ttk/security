<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Console\Commands;

use ArtisanPackUI\Security\Models\UserDevice;
use Illuminate\Console\Command;

class CleanupInactiveDevices extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'security:devices:cleanup
                            {--days=180 : Delete devices inactive for more than this many days}
                            {--keep-trusted : Keep trusted devices regardless of activity}
                            {--dry-run : Show what would be deleted without actually deleting}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Clean up inactive user devices';

    /**
     * Execute the console command.
     */
    public function handle(): int
    {
        $days = (int) $this->option('days');
        $keepTrusted = $this->option('keep-trusted');
        $dryRun = $this->option('dry-run');

        $this->info("Cleaning up devices inactive for more than {$days} days...");

        $query = UserDevice::where('last_active_at', '<', now()->subDays($days));

        if ($keepTrusted) {
            $query->where('is_trusted', false);
            $this->line('Keeping trusted devices');
        }

        $count = $query->count();
        $this->line("Found {$count} inactive devices");

        if ($dryRun) {
            $this->warn('Dry run mode - no devices were deleted');

            // Show breakdown by device type
            $breakdown = UserDevice::where('last_active_at', '<', now()->subDays($days))
                ->when($keepTrusted, fn ($q) => $q->where('is_trusted', false))
                ->selectRaw('type, count(*) as count')
                ->groupBy('type')
                ->pluck('count', 'type');

            if ($breakdown->isNotEmpty()) {
                $this->table(['Device Type', 'Count'], $breakdown->map(fn ($count, $type) => [$type, $count])->values());
            }

            return self::SUCCESS;
        }

        $deleted = $query->delete();
        $this->info("Deleted {$deleted} inactive device(s)");

        return self::SUCCESS;
    }
}
