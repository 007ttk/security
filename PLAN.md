# Plan for Enabling Session Encryption by Default

This document outlines the plan to enable session encryption by default in the `artisanpack/security` package. This change will enhance the security of applications using this package by protecting session data from being intercepted and read.

## Phase 1: Add Session Encryption Configuration

### File to Modify

`config/security.php`

### Change Details

A new configuration key, `encrypt`, will be added to the `security.php` configuration file. This setting will control whether session encryption is enforced.

- **Default Value:** `true`
- **Environment Variable:** The setting can be overridden using the `SESSION_ENCRYPT` environment variable.

### Proposed Code

The following snippet will be added to the `return` array in `config/security.php`:

```php
    /*
    |--------------------------------------------------------------------------
    | Enforce Session Encryption
    |--------------------------------------------------------------------------
    |
    | This option determines whether the package should enforce that the
    | application's session cookie is encrypted. When enabled, this
    | package will verify that session encryption is not disabled
    | in production environments.
    |
    */
    'encrypt' => env('SESSION_ENCRYPT', true),
```

## Phase 2: Implement Configuration Validation

To ensure that session encryption is not accidentally disabled in production, two validation mechanisms will be implemented.

### 1. Environment Validation Middleware

A new middleware will be created to check for session encryption when the application is in a production environment.

#### File to Create

`src/Http/Middleware/EnsureSessionIsEncrypted.php`

#### Logic

The middleware will perform the following checks:

1. Is the application environment `production`?
2. Is `config('artisanpack.security.encrypt')` set to `false`?

If both conditions are met, the middleware will throw a `\RuntimeException` to prevent the application from running with an insecure configuration.

#### Registration

The middleware will be registered in the `boot` method of `src/SecurityServiceProvider.php`. It will be pushed to the `web` middleware group.

### 2. Artisan Command

A new Artisan command will be created to allow developers to check the status of their session encryption configuration.

#### File to Create

`src/Console/Commands/CheckSessionSecurity.php`

#### Command Signature

```bash
php artisan security:check-session
```

#### Logic

The command will check the value of `config('artisanpack.security.encrypt')`.

- If `true`, it will output a success message.
- If `false`, it will output a warning. If the application environment is `production`, the warning will be more severe.

#### Registration

The command will be registered in the `boot` method of `src/SecurityServiceProvider.php` within the `if ($this->app->runningInConsole())` block.

## Phase 3: Documentation Updates

To communicate this change to users, the package documentation will be updated.

### 1. Migration Guide

A new migration guide will be created to help existing users upgrade.

#### File to Create

`docs/migration-guide-session-encryption.md`

#### Content

- Explanation that session encryption is now enabled by default.
- Instructions on how to use the `SESSION_ENCRYPT` environment variable to manage the setting.
- Information about the new `security:check-session` Artisan command.

### 2. Update Existing Documentation

The `security-guidelines.md` document will be updated to include the benefits of session encryption.

#### File to Modify

`docs/security-guidelines.md`

#### Content to Add

A new section will be added explaining:

- The importance of session encryption.
- How the package enforces session encryption in production.
- A reference to the new migration guide.

## Phase 4: Testing

To ensure the new functionality is working correctly and does not introduce any regressions, a suite of tests will be developed.

### Test Files to Create/Modify

- `tests/Unit/SessionEncryptionTest.php`
- `tests/Feature/CheckSessionSecurityCommandTest.php`
- `tests/Feature/EnsureSessionIsEncryptedMiddlewareTest.php`

### Test Cases

- **Unit Test:**
    - Verify that `config('artisanpack.security.encrypt')` defaults to `true`.
- **Feature Tests (Middleware):**
    - Test that the middleware allows requests when encryption is enabled.
    - Test that the middleware throws an exception in production when encryption is disabled.
    - Test that the middleware does not throw an exception in a non-production environment when encryption is disabled.
- **Feature Tests (Artisan Command):**
    - Test the command's output when session encryption is enabled.
    - Test the command's output when session encryption is disabled (non-production).
    - Test the command's output when session encryption is disabled (production).
