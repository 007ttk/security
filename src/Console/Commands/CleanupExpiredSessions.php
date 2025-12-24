<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Console\Commands;

use ArtisanPackUI\Security\Models\UserSession;
use Illuminate\Console\Command;

class CleanupExpiredSessions extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'security:sessions:cleanup
                            {--days=30 : Delete sessions older than this many days}
                            {--dry-run : Show what would be deleted without actually deleting}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Clean up expired and old user sessions';

    /**
     * Execute the console command.
     */
    public function handle(): int
    {
        $days = (int) $this->option('days');
        $dryRun = $this->option('dry-run');

        $this->info('Cleaning up expired sessions...');

        // Build a single query for sessions to clean up (expired OR inactive too long)
        // This prevents double-counting sessions that match both criteria
        $cleanupQuery = fn () => UserSession::where(function ($query) use ($days) {
            $query->where('expires_at', '<', now())
                ->orWhere('last_activity_at', '<', now()->subDays($days));
        });

        // Count sessions to be cleaned up (as a single set)
        $totalCount = $cleanupQuery()->count();

        // For informational purposes, show breakdown (may overlap)
        $expiredCount = UserSession::where('expires_at', '<', now())->count();
        $inactiveCount = UserSession::where('last_activity_at', '<', now()->subDays($days))->count();

        $this->line("Found {$expiredCount} expired sessions");
        $this->line("Found {$inactiveCount} sessions inactive for more than {$days} days");
        $this->line("Total unique sessions to clean: {$totalCount}");

        if ($dryRun) {
            $this->warn('Dry run mode - no sessions were deleted');

            return self::SUCCESS;
        }

        // Delete all matching sessions in a single operation
        $deleted = $cleanupQuery()->delete();
        $this->info("Deleted {$deleted} sessions");

        return self::SUCCESS;
    }
}
