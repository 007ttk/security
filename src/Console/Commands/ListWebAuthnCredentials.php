<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Console\Commands;

use ArtisanPackUI\Security\Models\WebAuthnCredential;
use Illuminate\Console\Command;

class ListWebAuthnCredentials extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'security:webauthn:list
                            {--user= : Filter by user ID or email}
                            {--type= : Filter by type (platform|cross-platform)}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'List WebAuthn credentials';

    /**
     * Execute the console command.
     */
    public function handle(): int
    {
        $query = WebAuthnCredential::with('user');

        if ($userId = $this->option('user')) {
            $userModel = config('auth.providers.users.model');
            $user = $userModel::where('id', $userId)
                ->orWhere('email', $userId)
                ->first();

            if (! $user) {
                $this->error("User not found: {$userId}");

                return self::FAILURE;
            }

            $query->where('user_id', $user->id);
            $this->info("Showing credentials for user: {$user->email}");
        }

        if ($type = $this->option('type')) {
            $isPlatform = $type === 'platform';
            $query->where('is_platform_credential', $isPlatform);
        }

        $credentials = $query->orderBy('created_at', 'desc')->get();

        if ($credentials->isEmpty()) {
            $this->info('No WebAuthn credentials found.');

            return self::SUCCESS;
        }

        $this->table(
            ['ID', 'User', 'Name', 'Type', 'Sign Count', 'Last Used', 'Created'],
            $credentials->map(fn ($c) => [
                \Illuminate\Support\Str::limit($c->id, 8),
                $c->user?->email ?? '-',
                $c->name,
                $c->is_platform_credential ? 'Biometric' : 'Security Key',
                $c->sign_count,
                $c->last_used_at?->diffForHumans() ?? 'Never',
                $c->created_at->format('Y-m-d'),
            ])
        );

        $this->line('');
        $this->line("Total: {$credentials->count()} credential(s)");

        return self::SUCCESS;
    }
}
