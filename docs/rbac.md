# Role-Based Access Control (RBAC)

This package provides a flexible Role-Based Access Control (RBAC) system to manage user permissions.

## Enabling the RBAC Module

The RBAC module is enabled by default. To disable it, you can set the `enabled` option in `config/artisanpack/security.php` to `false`:

```php
// config/artisanpack/security.php
'rbac' => [
    'enabled' => false,
],
```

When disabled, the package will not register any RBAC-related migrations, commands, or middleware.

## Database Schema

The RBAC system introduces four new tables:

- `roles`: Stores roles.
- `permissions`: Stores permissions.
- `role_user`: Attaches roles to users.
- `permission_role`: Attaches permissions to roles.

## Models and Trait

### HasRoles Trait

To add RBAC functionality to your `User` model, simply use the `ArtisanPackUI\Security\Concerns\HasRoles` trait:

```php
use Illuminate\Foundation\Auth\User as Authenticatable;
use ArtisanPackUI\Security\Concerns\HasRoles;

class User extends Authenticatable
{
    use HasRoles;

    // ...
}
```

### Role and Permission Models

The package provides `ArtisanPackUI\Security\Models\Role` and `ArtisanPackUI\Security\Models\Permission` models.

## Usage

### Checking for Roles and Permissions

You can check if a user has a specific role or permission using the methods provided by the `HasRoles` trait:

```php
// Check if a user has a role
$user->hasRole('admin');

// Check if a user has a permission
$user->hasPermission('edit-articles');

// or using the can() method
$user->can('edit-articles');
```

### Blade Directives

The package includes Blade directives for checking roles and permissions in your views:

```blade
@role('admin')
    <p>This is visible to users with the admin role.</p>
@endrole

@permission('edit-articles')
    <p>This is visible to users with the 'edit-articles' permission.</p>
@endpermission
```

### Middleware

You can protect your routes with the `permission` middleware:

```php
Route::get('/dashboard', function () {
    // ...
})->middleware('permission:access-dashboard');
```

## Role Inheritance

Roles can inherit permissions from a parent role. To define a parent role, set the `parent_id` when creating a role.

## Artisan Commands

The package provides Artisan commands to manage roles and permissions:

- `php artisan role:create {name}`: Create a new role.
- `php artisan permission:create {name}`: Create a new permission.
- `php artisan user:assign-role {user_id} {role_name}`: Assign a role to a user.
- `php artisan user:revoke-role {user_id} {role_name}`: Revoke a role from a user.
