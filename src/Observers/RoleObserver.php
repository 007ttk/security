<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Observers;

use ArtisanPackUI\Security\Contracts\SecurityEventLoggerInterface;
use ArtisanPackUI\Security\Models\Role;
use ArtisanPackUI\Security\Models\SecurityEvent;

class RoleObserver
{
    public function __construct(
        protected SecurityEventLoggerInterface $logger
    ) {}

    /**
     * Handle the Role "created" event.
     */
    public function created(Role $role): void
    {
        $this->logger->roleChange('role_created', [
            'role_id' => $role->id,
            'role_name' => $role->name,
            'description' => $role->description,
            'parent_id' => $role->parent_id,
        ], SecurityEvent::SEVERITY_INFO);
    }

    /**
     * Handle the Role "updated" event.
     */
    public function updated(Role $role): void
    {
        $changes = $role->getChanges();
        $original = $role->getOriginal();

        $this->logger->roleChange('role_updated', [
            'role_id' => $role->id,
            'role_name' => $role->name,
            'changes' => array_keys($changes),
            'original' => array_intersect_key($original, $changes),
            'new' => array_intersect_key($role->toArray(), $changes),
        ], SecurityEvent::SEVERITY_INFO);
    }

    /**
     * Handle the Role "deleted" event.
     */
    public function deleted(Role $role): void
    {
        $this->logger->roleChange('role_deleted', [
            'role_id' => $role->id,
            'role_name' => $role->name,
        ], SecurityEvent::SEVERITY_WARNING);
    }

    /**
     * Handle permissions being attached to a role.
     */
    public function pivotAttached(Role $role, string $relationName, array $pivotIds): void
    {
        if ($relationName === 'permissions') {
            $this->logger->roleChange('role_permissions_attached', [
                'role_id' => $role->id,
                'role_name' => $role->name,
                'permission_ids' => $pivotIds,
            ], SecurityEvent::SEVERITY_INFO);
        }

        if ($relationName === 'users') {
            $this->logger->roleChange('role_users_attached', [
                'role_id' => $role->id,
                'role_name' => $role->name,
                'user_ids' => $pivotIds,
            ], SecurityEvent::SEVERITY_INFO);
        }
    }

    /**
     * Handle permissions being detached from a role.
     */
    public function pivotDetached(Role $role, string $relationName, array $pivotIds): void
    {
        if ($relationName === 'permissions') {
            $this->logger->roleChange('role_permissions_detached', [
                'role_id' => $role->id,
                'role_name' => $role->name,
                'permission_ids' => $pivotIds,
            ], SecurityEvent::SEVERITY_INFO);
        }

        if ($relationName === 'users') {
            $this->logger->roleChange('role_users_detached', [
                'role_id' => $role->id,
                'role_name' => $role->name,
                'user_ids' => $pivotIds,
            ], SecurityEvent::SEVERITY_INFO);
        }
    }
}
