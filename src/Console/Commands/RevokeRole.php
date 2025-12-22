<?php

namespace ArtisanPackUI\Security\Console\Commands;

use ArtisanPackUI\Security\Models\Role;
use Illuminate\Console\Command;

class RevokeRole extends Command
{
    protected $signature = 'user:revoke-role {user} {role}';
    protected $description = 'Revoke a role from a user';

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

        $user->roles()->detach($role);

        if (method_exists($user, 'flushPermissionCache')) {
            $user->flushPermissionCache();
        }

        $this->info("Role `{$role->name}` revoked from user `{$user->name}` successfully.");
    }
}
