<?php

namespace ArtisanPackUI\Security\Console\Commands;

use Illuminate\Console\Command;

class CheckSessionSecurity extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'security:check-session';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Check if session encryption is enabled';

    /**
     * Execute the console command.
     *
     * @return int
     */
    public function handle()
    {
        $sessionIsEncrypted = config('artisanpack.security.encrypt');

        if ($sessionIsEncrypted) {
            $this->info('Session encryption is enabled.');
            return 0;
        }

        $this->warn('Session encryption is disabled.');

        if (app()->environment('production')) {
            $this->error('WARNING: Session encryption is disabled in a production environment. This is a major security risk.');
            return 1;
        }

        return 0;
    }
}
