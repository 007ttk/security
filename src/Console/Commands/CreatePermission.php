<?php

namespace ArtisanPackUI\Security\Console\Commands;

use ArtisanPackUI\Security\Models\Permission;
use Illuminate\Console\Command;

class CreatePermission extends Command
{
    protected $signature = 'permission:create {name}';
    protected $description = 'Create a new permission';

    public function handle()
    {
        $permission = Permission::create(['name' => $this->argument('name')]);
        $this->info("Permission `{$permission->name}` created successfully.");
    }
}
