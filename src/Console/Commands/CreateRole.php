<?php

namespace ArtisanPackUI\Security\Console\Commands;

use ArtisanPackUI\Security\Models\Role;
use Illuminate\Console\Command;

class CreateRole extends Command
{
    protected $signature = 'role:create {name}';
    protected $description = 'Create a new role';

    public function handle()
    {
        $role = Role::create(['name' => $this->argument('name')]);
        $this->info("Role `{$role->name}` created successfully.");
    }
}
