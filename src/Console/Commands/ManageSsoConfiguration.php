<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Console\Commands;

use ArtisanPackUI\Security\Models\SsoConfiguration;
use Illuminate\Console\Command;

class ManageSsoConfiguration extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'security:sso
                            {action : The action to perform (list|create|enable|disable|delete)}
                            {--id= : SSO configuration ID}
                            {--name= : Configuration name}
                            {--protocol= : Protocol (saml|oidc|ldap)}
                            {--domain= : Associated domain}
                            {--entity-id= : Entity ID for SAML}
                            {--sso-url= : SSO URL}
                            {--certificate= : Path to certificate file}
                            {--force : Skip confirmation for destructive actions}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Manage SSO configurations';

    /**
     * Execute the console command.
     */
    public function handle(): int
    {
        $action = $this->argument('action');

        return match ($action) {
            'list' => $this->listConfigurations(),
            'create' => $this->createConfiguration(),
            'enable' => $this->toggleConfiguration(true),
            'disable' => $this->toggleConfiguration(false),
            'delete' => $this->deleteConfiguration(),
            default => $this->invalidAction($action),
        };
    }

    protected function listConfigurations(): int
    {
        $configs = SsoConfiguration::all();

        if ($configs->isEmpty()) {
            $this->info('No SSO configurations found.');

            return self::SUCCESS;
        }

        $this->table(
            ['ID', 'Name', 'Protocol', 'Domain', 'Enabled', 'Created At'],
            $configs->map(fn ($c) => [
                $c->id,
                $c->name,
                $c->protocol,
                $c->domain ?? '-',
                $c->is_active ? 'Yes' : 'No',
                $c->created_at->format('Y-m-d H:i'),
            ])
        );

        return self::SUCCESS;
    }

    protected function createConfiguration(): int
    {
        $name = $this->option('name') ?? $this->ask('Configuration name');
        $protocol = $this->option('protocol') ?? $this->choice('Protocol', ['saml', 'oidc', 'ldap']);
        $domain = $this->option('domain') ?? $this->ask('Associated domain (optional)', null);

        $settings = [];

        if ($protocol === 'saml') {
            $settings['entity_id'] = $this->option('entity-id') ?? $this->ask('Entity ID');
            $settings['sso_url'] = $this->option('sso-url') ?? $this->ask('SSO URL');

            if ($certPath = $this->option('certificate')) {
                if (file_exists($certPath)) {
                    $certificate = @file_get_contents($certPath);
                    if ($certificate === false) {
                        $this->error("Failed to read certificate file: {$certPath}");
                        return self::FAILURE;
                    }
                    $settings['certificate'] = $certificate;
                } else {
                    $this->error("Certificate file not found: {$certPath}");

                    return self::FAILURE;
                }
            }
        } elseif ($protocol === 'oidc') {
            $settings['client_id'] = $this->ask('Client ID');
            $settings['client_secret'] = $this->secret('Client Secret');
            $settings['issuer'] = $this->ask('Issuer URL');
        } elseif ($protocol === 'ldap') {
            $settings['host'] = $this->ask('LDAP Host');
            $settings['port'] = $this->ask('LDAP Port', '389');
            $settings['base_dn'] = $this->ask('Base DN');
            $settings['bind_dn'] = $this->ask('Bind DN (for authenticated LDAP)', null);
            if ($settings['bind_dn']) {
                $settings['password'] = $this->secret('Bind Password');
            }
        }

        // Generate unique slug
        $slug = \Illuminate\Support\Str::slug($name);
        $originalSlug = $slug;
        $counter = 1;

        while (SsoConfiguration::where('slug', $slug)->exists()) {
            $slug = $originalSlug.'-'.$counter++;
        }

        $config = SsoConfiguration::create([
            'name' => $name,
            'slug' => $slug,
            'protocol' => $protocol,
            'domain' => $domain,
            'settings' => $settings,
            'is_active' => true,
        ]);

        $this->info("SSO configuration created with ID: {$config->id}");

        return self::SUCCESS;
    }

    protected function toggleConfiguration(bool $enable): int
    {
        $id = $this->option('id') ?? $this->ask('Configuration ID');
        $config = SsoConfiguration::find($id);

        if (! $config) {
            $this->error("Configuration not found: {$id}");

            return self::FAILURE;
        }

        $config->update(['is_active' => $enable]);
        $status = $enable ? 'enabled' : 'disabled';
        $this->info("SSO configuration '{$config->name}' has been {$status}.");

        return self::SUCCESS;
    }

    protected function deleteConfiguration(): int
    {
        $id = $this->option('id') ?? $this->ask('Configuration ID');
        $config = SsoConfiguration::find($id);

        if (! $config) {
            $this->error("Configuration not found: {$id}");

            return self::FAILURE;
        }

        if (! $this->option('force') && ! $this->confirm("Are you sure you want to delete '{$config->name}'?")) {
            $this->info('Operation cancelled.');

            return self::SUCCESS;
        }

        $config->delete();
        $this->info("SSO configuration '{$config->name}' has been deleted.");

        return self::SUCCESS;
    }

    protected function invalidAction(string $action): int
    {
        $this->error("Invalid action: {$action}");
        $this->line('Valid actions: list, create, enable, disable, delete');

        return self::FAILURE;
    }
}
