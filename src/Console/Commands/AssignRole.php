<?php

namespace ArtisanPackUI\Security\Console\Commands;

use ArtisanPackUI\Security\Models\Role;
use Illuminate\Console\Command;

class AssignRole extends Command
{
    protected $signature = 'user:assign-role {user : The user ID, email, or username} {role : The role name}';
    protected $description = 'Assign a role to a user';

    public function handle()
    {
        $userModel = config('auth.providers.users.model');
        $userArgument = $this->argument('user');
        $role = Role::where('name', $this->argument('role'))->first();

        $user = is_numeric($userArgument)
            ? $userModel::find($userArgument)
            : $userModel::where('email', $userArgument)->orWhere('username', $userArgument)->first();


        if (!$user) {
            $this->error('User not found.');
            return;
        }

        if (!$role) {
            $this->error('Role not found.');
            return;
        }

        $user->roles()->syncWithoutDetaching([$role->id]);
        
        if (method_exists($user, 'flushPermissionCache')) {
            $user->flushPermissionCache();
        }

        $this->info("Role `{$role->name}` assigned to user `{$user->name}` successfully.");
    }
}
