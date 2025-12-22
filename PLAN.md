# Overall Considerations

To prevent conflicts with existing RBAC implementations in other packages (e.g., `artisanpack-ui/cms-framework`), a configurable setting will be introduced. This setting will allow for enabling or disabling the RBAC features provided by this package, ensuring compatibility and flexibility for applications that already have established roles, permissions, role_user, and permission_role tables and models.

### Implementation Details

1.  **Configuration Setting:**
    -   A new `rbac` key will be added to the `config/security.php` file.
    -   This key will contain an `enabled` boolean flag:
        ```php
        // config/security.php
        return [
            // ... other settings
            'rbac' => [
                'enabled' => env('SECURITY_RBAC_ENABLED', true),
            ],
        ];
        ```

2.  **Conditional Loading in Service Provider:**
    -   The `SecurityServiceProvider.php` will check the value of `config('security.rbac.enabled')`.
    -   If the value is `true`, the service provider will proceed with registering all RBAC-related components:
        -   It will load the migrations for the `roles`, `permissions`, `permission_role`, and `role_user` tables.
        -   It will register the RBAC-related Artisan commands (e.g., `user:assign-role`).
        -   It will register the `CheckPermission` middleware.
        -   It will register the `@role` and `@permission` Blade directives.
    -   If the value is `false`, all the above components will be skipped, effectively disabling the RBAC functionality of this package and preventing any potential conflicts.
    -   The `HasRoles` trait will remain available, but since none of the supporting infrastructure will be registered, it will not interfere with any existing RBAC system.

# Role-Based Access Control (RBAC) Implementation Plan

This document outlines the plan to implement a comprehensive Role-Based Access Control (RBAC) system for the application.

## 1. Database Schema Design

**Status:** Not started.

We will create four new tables to manage roles, permissions, and their relationships:

-   `roles`: Stores role information (e.g., name, description).
-   `permissions`: Stores permission information (e.g., name, description).
-   `permission_role` (pivot table): Manages the many-to-many relationship between roles and permissions.
-   `role_user` (pivot table): Manages the many-to-many relationship between users and roles.

### `roles` table schema:
-   `id` (Primary Key, unsigned Big Integer)
-   `name` (String, unique)
-   `description` (String, nullable)
-   `parent_id` (unsigned Big Integer, nullable, foreign key to `roles.id` for inheritance)
-   `created_at`, `updated_at` (Timestamps)

### `permissions` table schema:
-   `id` (Primary Key, unsigned Big Integer)
-   `name` (String, unique)
-   `description` (String, nullable)
-   `created_at`, `updated_at` (Timestamps)

### `permission_role` table schema:
-   `permission_id` (Foreign Key to `permissions.id`)
-   `role_id` (Foreign Key to `roles.id`)

### `role_user` table schema:
-   `role_id` (Foreign Key to `roles.id`)
-   `user_id` (Foreign Key to `users.id`)

## 2. Create Migrations and Seeding

**Status:** Not started.

We will create migration files for the new tables and a seeder to populate them with initial data.

**Action:**
- Create four migration files for the `roles`, `permissions`, `permission_role`, and `role_user` tables.
- Create a `RolesAndPermissionsSeeder` to populate the `roles` and `permissions` tables with some default roles (e.g., `admin`, `user`) and permissions.

## 3. Create Models and Relationships

**Status:** Not started.

We will create the `Role` and `Permission` models and define the necessary relationships.

**Action:**
- Create the `app/Models/Role.php` model.
- Create the `app/Models/Permission.php` model.
- In the `Role` model, define the `permissions()` and `users()` many-to-many relationships.
- In the `Permission` model, define the `roles()` many-to-many relationship.
- In the `App\Models\User` model, we will add a `HasRoles` trait.

## 4. Implement User-Role Relationships (`HasRoles` Trait)

**Status:** Not started.

A trait will be created to add RBAC functionality to the `User` model.

**Action:**
- Create a new file: `src/Concerns/HasRoles.php`.
- The `HasRoles` trait will contain the following methods:
    - `roles()`: The many-to-many relationship to the `Role` model.
    - `hasRole($role)`: Checks if the user has a specific role.
    - `hasPermission($permission)`: Checks if the user has a specific permission through their roles. This method will implement a caching layer using `Cache::remember()` to improve performance.
    - `can($permission)`: An alias for `hasPermission()`.
- The `User` model will then use this trait.

## 5. Authorization Policies and Gates

**Status:** Not started.

We will use Laravel Gates to define the application's permissions.

**Action:**
- Create a new service provider, `AuthServiceProvider.php`, if one doesn't exist.
- In the `boot()` method of the `AuthServiceProvider`, we will iterate through all the permissions from the database and define a Gate for each one.
- The Gate will use the `hasPermission()` method on the `User` model to check if the user has the required permission.

## 6. Role-based Middleware

**Status:** Not started.

A middleware will be created to protect routes based on roles or permissions.

**Action:**
- Create a new file: `src/Http/Middleware/CheckPermission.php`.
- The middleware will accept a parameter, which is the name of the permission required to access the route.
- It will use `Auth::user()->can($permission)` to check if the user has the required permission.
- If the user does not have the permission, it will abort with a 403 Forbidden response.
- Register the middleware in `app/Http/Kernel.php` with the alias `permission`.

## 7. Permission Checking Utilities

**Status:** Mostly complete.

The `HasRoles` trait will provide the `hasRole()`, `hasPermission()`, and `can()` methods. We will also add Blade directives for convenience in the views.

**Action:**
- In the `AuthServiceProvider`, add the following Blade directives:
    - `@role('admin')`: Checks if the user has the 'admin' role.
    - `@permission('edit-articles')`: Checks if the user has the 'edit-articles' permission.

## 8. Role Management UI Components

**Status:** Not started.

Since we can't create full UI components, we will outline the necessary Blade components.

**Action:**
- **`role-index.blade.php`:** A component to list all roles and provide options to edit or delete them.
- **`role-form.blade.php`:** A form component for creating and editing roles. It will include fields for the role name, description, and a multi-select box to assign permissions.
- **`assign-roles.blade.php`:** A component to be used on the user management page to assign roles to users.

## 9. Role Assignment Artisan Commands

**Status:** Not started.

Artisan commands will be created to manage roles and permissions from the command line.

**Action:**
- Create a new command: `user:assign-role {user} {role}`. This command will assign a role to a user.
- Create a new command: `user:revoke-role {user} {role}`. This command will revoke a role from a user.
- Create a new command: `role:create {name}`. This command will create a new role.
- Create a new command: `permission:create {name}`. This command will create a new permission.

## 10. Role Inheritance System

**Status:** Not started.

We will implement a simple role inheritance system using the `parent_id` in the `roles` table.

**Action:**
- When checking for permissions, if a role has a parent, the permissions of the parent role will also be checked recursively.
- The `hasPermission()` method in the `HasRoles` trait will be updated to handle this recursive check.

## 11. Create Comprehensive Test Suite

**Status:** Not started.

We will create tests for all the new functionality.

**Action:**
- **Unit Tests:**
    - Test the relationships on the `User`, `Role`, and `Permission` models.
    - Test the methods in the `HasRoles` trait.
- **Feature Tests:**
    - Test the `CheckPermission` middleware.
    - Test the Gates and Blade directives.
    - Test the Artisan commands.

## 12. Document RBAC Implementation Patterns

**Status:** Not started.

A new documentation page will be created to explain the RBAC system.

**Action:**
- Create a new documentation file: `docs/rbac.md`.
- This document will cover:
    - The database schema.
    - How to create and manage roles and permissions.
    - How to use the `HasRoles` trait.
    - How to protect routes with the `permission` middleware.
    - How to use the Blade directives.
    - How to use the Artisan commands.
    - An explanation of the role inheritance system.
- Update the main `README.md` or `home.md` to link to the new documentation page.