<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Console\Commands;

use ArtisanPackUI\Security\Authentication\Session\AdvancedSessionManager;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\App;

class TerminateUserSessions extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'security:sessions:terminate
                            {user : The user ID or email}
                            {--force : Skip confirmation}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Terminate all sessions for a specific user';

    /**
     * Execute the console command.
     */
    public function handle(): int
    {
        $userIdentifier = $this->argument('user');

        // Find the user
        $userModel = config('auth.providers.users.model');
        $user = $userModel::where('id', $userIdentifier)
            ->orWhere('email', $userIdentifier)
            ->first();

        if (! $user) {
            $this->error("User not found: {$userIdentifier}");

            return self::FAILURE;
        }

        $this->info("User: {$user->email} (ID: {$user->id})");

        // Count active sessions
        $sessionCount = $user->userSessions()->active()->count();
        $this->line("Active sessions: {$sessionCount}");

        if ($sessionCount === 0) {
            $this->info('No active sessions to terminate.');

            return self::SUCCESS;
        }

        if (! $this->option('force') && ! $this->confirm('Are you sure you want to terminate all sessions for this user?')) {
            $this->info('Operation cancelled.');

            return self::SUCCESS;
        }

        /** @var AdvancedSessionManager $sessionManager */
        $sessionManager = App::make(AdvancedSessionManager::class);
        $count = $sessionManager->terminateAllUserSessions($user);

        $this->info("Successfully terminated {$count} session(s).");

        return self::SUCCESS;
    }
}
