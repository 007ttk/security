<?php

declare(strict_types=1);

namespace ArtisanPackUI\Security\Observers;

use ArtisanPackUI\Security\Contracts\SecurityEventLoggerInterface;
use ArtisanPackUI\Security\Models\Permission;
use ArtisanPackUI\Security\Models\SecurityEvent;

class PermissionObserver
{
    public function __construct(
        protected SecurityEventLoggerInterface $logger
    ) {}

    /**
     * Handle the Permission "created" event.
     */
    public function created(Permission $permission): void
    {
        $this->logger->permissionChange('permission_created', [
            'permission_id' => $permission->id,
            'permission_name' => $permission->name,
            'description' => $permission->description,
        ], SecurityEvent::SEVERITY_INFO);
    }

    /**
     * Handle the Permission "updated" event.
     */
    public function updated(Permission $permission): void
    {
        $changes = $permission->getChanges();
        $original = $permission->getOriginal();

        $this->logger->permissionChange('permission_updated', [
            'permission_id' => $permission->id,
            'permission_name' => $permission->name,
            'changes' => array_keys($changes),
            'original' => array_intersect_key($original, $changes),
            'new' => array_intersect_key($permission->toArray(), $changes),
        ], SecurityEvent::SEVERITY_INFO);
    }

    /**
     * Handle the Permission "deleted" event.
     */
    public function deleted(Permission $permission): void
    {
        $this->logger->permissionChange('permission_deleted', [
            'permission_id' => $permission->id,
            'permission_name' => $permission->name,
        ], SecurityEvent::SEVERITY_WARNING);
    }

    /**
     * Handle roles being attached to a permission.
     */
    public function pivotAttached(Permission $permission, string $relationName, array $pivotIds): void
    {
        if ($relationName === 'roles') {
            $this->logger->permissionChange('permission_roles_attached', [
                'permission_id' => $permission->id,
                'permission_name' => $permission->name,
                'role_ids' => $pivotIds,
            ], SecurityEvent::SEVERITY_INFO);
        }
    }

    /**
     * Handle roles being detached from a permission.
     */
    public function pivotDetached(Permission $permission, string $relationName, array $pivotIds): void
    {
        if ($relationName === 'roles') {
            $this->logger->permissionChange('permission_roles_detached', [
                'permission_id' => $permission->id,
                'permission_name' => $permission->name,
                'role_ids' => $pivotIds,
            ], SecurityEvent::SEVERITY_INFO);
        }
    }
}
