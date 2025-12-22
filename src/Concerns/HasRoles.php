<?php

namespace ArtisanPackUI\Security\Concerns;

use ArtisanPackUI\Security\Models\Role;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;
use Illuminate\Support\Facades\Cache;

trait HasRoles
{
    public function roles(): BelongsToMany
    {
        return $this->belongsToMany(
            Role::class,
            $this->getRoleUserPivotTable(),
            $this->getRoleUserForeignKey(),
            'role_id'
        );
    }

    /**
     * Get the pivot table name for role-user relationships.
     * Override this method in your model to customize.
     */
    protected function getRoleUserPivotTable(): string
    {
        return config('artisanpack.security.rbac.tables.role_user', 'role_user');
    }

    /**
     * Get the foreign key name for the user in the pivot table.
     * Override this method in your model to customize.
     */
    protected function getRoleUserForeignKey(): string
    {
        return config('artisanpack.security.rbac.foreign_keys.user', 'user_id');
    }

    public function hasRole($role): bool
    {
        if (is_string($role)) {
            return $this->roles->contains('name', $role);
        }

        if ($role instanceof Role) {
            return $this->roles->contains('id', $role->getKey());
        }

        // Assume it's a collection of roles
        return (bool) $role->intersect($this->roles)->count();
    }

    public function hasPermission($permission): bool
    {
        $cacheKey = 'permissions_for_user_' . $this->id;

        $permissions = $this->cacheSupportsTagging()
            ? Cache::tags(['permissions'])->remember($cacheKey, 60, fn () => $this->loadAllPermissions())
            : Cache::remember($cacheKey, 60, fn () => $this->loadAllPermissions());

        return $permissions->contains('name', $permission);
    }

    public function flushPermissionCache(): void
    {
        $cacheKey = 'permissions_for_user_' . $this->id;

        if ($this->cacheSupportsTagging()) {
            Cache::tags(['permissions'])->forget($cacheKey);
        } else {
            Cache::forget($cacheKey);
        }
    }

    protected function cacheSupportsTagging(): bool
    {
        return Cache::getStore() instanceof \Illuminate\Cache\TaggableStore;
    }

    protected function loadAllPermissions(): \Illuminate\Support\Collection
    {
        $allPermissions = collect();

        $this->roles->each(function ($role) use (&$allPermissions) {
            $allPermissions = $allPermissions->merge($this->getAllPermissionsForRole($role));
        });

        return $allPermissions;
    }

    protected function getAllPermissionsForRole(Role $role, array $visited = []): \Illuminate\Support\Collection
    {
        if (in_array($role->id, $visited)) {
            return collect();
        }
        
        $visited[] = $role->id;
        $permissions = $role->permissions;

        if ($role->parent) {
            $permissions = $permissions->merge($this->getAllPermissionsForRole($role->parent, $visited));
        }

        return $permissions;
    }
}
