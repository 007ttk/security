---
title: Compliance Framework Guide
---

# Compliance Framework Guide

This guide covers the compliance and data protection features including GDPR compliance, consent management, data retention, audit logging, and compliance reporting.

## Overview

The ArtisanPack Security package provides comprehensive compliance features:

- **GDPR Compliance**: Data subject rights, consent management, data portability
- **Consent Management**: Track and manage user consent for data processing
- **Data Retention**: Automated data lifecycle management
- **Audit Logging**: Comprehensive activity tracking for compliance
- **Compliance Reporting**: Generate reports for auditors and regulators
- **Data Anonymization**: Safely anonymize user data

## Configuration

Configure compliance features in `config/artisanpack/security.php`:

```php
'compliance' => [
    'enabled' => env('SECURITY_COMPLIANCE_ENABLED', true),

    'gdpr' => [
        'enabled' => true,
        'data_portability' => true,
        'right_to_erasure' => true,
        'consent_required' => true,
    ],

    'consent' => [
        'enabled' => true,
        'categories' => [
            'necessary' => [
                'name' => 'Necessary',
                'description' => 'Required for the website to function',
                'required' => true,
            ],
            'analytics' => [
                'name' => 'Analytics',
                'description' => 'Help us understand how visitors use our site',
                'required' => false,
            ],
            'marketing' => [
                'name' => 'Marketing',
                'description' => 'Used for personalized advertising',
                'required' => false,
            ],
            'preferences' => [
                'name' => 'Preferences',
                'description' => 'Remember your settings and preferences',
                'required' => false,
            ],
        ],
        'version' => '1.0',
        'expiry_days' => 365,
    ],

    'data_retention' => [
        'enabled' => true,
        'policies' => [
            'security_logs' => 90,      // Days
            'audit_logs' => 365,
            'session_data' => 30,
            'failed_logins' => 30,
            'api_logs' => 90,
        ],
        'auto_cleanup' => true,
        'cleanup_schedule' => 'daily',
    ],

    'audit_logging' => [
        'enabled' => true,
        'log_reads' => false,           // Log data access (verbose)
        'log_writes' => true,           // Log data modifications
        'log_deletions' => true,        // Log data deletions
        'log_exports' => true,          // Log data exports
        'include_ip' => true,
        'include_user_agent' => true,
    ],

    'anonymization' => [
        'enabled' => true,
        'method' => 'pseudonymize',     // 'delete', 'pseudonymize', 'encrypt'
        'retain_analytics' => true,     // Keep anonymized data for analytics
    ],
],
```

## GDPR Compliance

### Data Subject Rights

The package implements all GDPR data subject rights:

| Right | Implementation |
|-------|----------------|
| Right to Access | Data export functionality |
| Right to Rectification | Profile editing capabilities |
| Right to Erasure | Account deletion with data removal |
| Right to Restrict Processing | Consent withdrawal |
| Right to Data Portability | JSON/CSV export |
| Right to Object | Marketing opt-out |

### User Model Setup

Add the GDPR trait to your User model:

```php
use ArtisanPackUI\Security\Concerns\HasGdprFeatures;

class User extends Authenticatable
{
    use HasGdprFeatures;
}
```

### Data Export (Right to Access)

```php
use ArtisanPackUI\Security\Services\GdprService;

class GdprController extends Controller
{
    public function export(Request $request, GdprService $gdpr)
    {
        $user = $request->user();

        // Generate comprehensive data export
        $export = $gdpr->exportUserData($user);

        return response()->json($export);
    }

    public function downloadExport(Request $request, GdprService $gdpr)
    {
        $user = $request->user();

        // Generate downloadable ZIP with all user data
        $zipPath = $gdpr->generateDataPackage($user);

        return response()->download($zipPath, 'my-data.zip')
            ->deleteFileAfterSend();
    }
}
```

The export includes:

- Profile information
- Account settings
- Activity history
- Uploaded files metadata
- Consent records
- Login history
- API tokens (hashed)
- Associated data from related models

### Customizing Export Data

Define exportable data in your models:

```php
use ArtisanPackUI\Security\Contracts\GdprExportable;

class Order extends Model implements GdprExportable
{
    public function getGdprExportData(): array
    {
        return [
            'id' => $this->id,
            'order_number' => $this->order_number,
            'total' => $this->total,
            'status' => $this->status,
            'created_at' => $this->created_at->toIso8601String(),
            'items' => $this->items->map(fn($item) => [
                'product' => $item->product_name,
                'quantity' => $item->quantity,
                'price' => $item->price,
            ])->toArray(),
        ];
    }

    public function getGdprExportLabel(): string
    {
        return 'Orders';
    }
}

// Register in User model
public function getGdprRelations(): array
{
    return [
        'orders' => Order::class,
        'comments' => Comment::class,
        'subscriptions' => Subscription::class,
    ];
}
```

### Right to Erasure (Account Deletion)

```php
use ArtisanPackUI\Security\Services\GdprService;

class AccountController extends Controller
{
    public function destroy(Request $request, GdprService $gdpr)
    {
        $request->validate([
            'password' => 'required|current_password',
            'confirm' => 'required|accepted',
        ]);

        $user = $request->user();

        // Process deletion request
        $gdpr->processErasureRequest($user, [
            'reason' => $request->input('reason'),
            'feedback' => $request->input('feedback'),
        ]);

        Auth::logout();

        return redirect('/')->with('message', 'Account deleted successfully.');
    }
}
```

### Erasure Strategies

Configure how data is handled during erasure:

```php
'anonymization' => [
    'method' => 'pseudonymize',  // Options below
],
```

| Method | Behavior |
|--------|----------|
| `delete` | Completely remove all data |
| `pseudonymize` | Replace identifying data with pseudonyms |
| `encrypt` | Encrypt data with a key that can be destroyed |

### Custom Erasure Handling

```php
use ArtisanPackUI\Security\Contracts\GdprErasable;

class Comment extends Model implements GdprErasable
{
    public function handleGdprErasure(): void
    {
        // Option 1: Anonymize
        $this->update([
            'author_name' => 'Deleted User',
            'email' => null,
        ]);

        // Option 2: Delete entirely
        // $this->delete();
    }
}
```

## Consent Management

### Configuration

```php
'consent' => [
    'enabled' => true,
    'categories' => [
        'necessary' => [
            'name' => 'Necessary',
            'description' => 'Required for the website to function properly.',
            'required' => true,  // Cannot be declined
        ],
        'analytics' => [
            'name' => 'Analytics',
            'description' => 'Help us understand how visitors interact with our website.',
            'required' => false,
        ],
        'marketing' => [
            'name' => 'Marketing',
            'description' => 'Used to deliver personalized advertisements.',
            'required' => false,
        ],
    ],
],
```

### Consent Banner Component

```blade
<livewire:consent-banner />
```

Or build a custom implementation:

```php
use ArtisanPackUI\Security\Services\ConsentService;

class ConsentController extends Controller
{
    public function show(ConsentService $consent)
    {
        return view('consent.banner', [
            'categories' => $consent->getCategories(),
            'currentConsent' => $consent->getCurrentConsent(request()),
        ]);
    }

    public function store(Request $request, ConsentService $consent)
    {
        $validated = $request->validate([
            'consents' => 'required|array',
            'consents.*' => 'boolean',
        ]);

        $consent->recordConsent(
            $request->user(),
            $validated['consents'],
            [
                'ip_address' => $request->ip(),
                'user_agent' => $request->userAgent(),
            ]
        );

        return response()->json(['success' => true]);
    }
}
```

### Checking Consent

```php
use ArtisanPackUI\Security\Facades\Consent;

// Check if user has given consent for a category
if (Consent::hasConsent($user, 'analytics')) {
    // Track analytics
}

if (Consent::hasConsent($user, 'marketing')) {
    // Show personalized ads
}

// In Blade templates
@if(hasConsent('analytics'))
    <!-- Google Analytics code -->
@endif
```

### Consent History

```php
// Get consent history for a user
$history = $user->consentHistory;

foreach ($history as $record) {
    echo $record->category;      // 'analytics'
    echo $record->granted;       // true/false
    echo $record->granted_at;    // Carbon date
    echo $record->ip_address;    // IP when consent was given
    echo $record->version;       // Consent policy version
}
```

### Consent Versioning

When your privacy policy changes, update the consent version:

```php
'consent' => [
    'version' => '2.0',  // Increment when policy changes
],
```

Users will be prompted to re-consent when the version changes:

```php
if (Consent::needsRenewal($user)) {
    return redirect()->route('consent.show');
}
```

## Data Retention

### Configuration

```php
'data_retention' => [
    'enabled' => true,
    'policies' => [
        'security_logs' => 90,
        'audit_logs' => 365,
        'session_data' => 30,
        'failed_logins' => 30,
        'api_logs' => 90,
        'user_activity' => 180,
    ],
    'auto_cleanup' => true,
    'cleanup_schedule' => 'daily',
],
```

### Manual Cleanup

```bash
# Run data retention cleanup
php artisan compliance:cleanup

# Preview what will be deleted (dry run)
php artisan compliance:cleanup --dry-run

# Clean specific data type
php artisan compliance:cleanup --type=security_logs

# Force cleanup ignoring schedule
php artisan compliance:cleanup --force
```

### Custom Retention Policies

```php
use ArtisanPackUI\Security\Contracts\HasRetentionPolicy;

class ActivityLog extends Model implements HasRetentionPolicy
{
    public function getRetentionDays(): int
    {
        return 90;
    }

    public function getRetentionScope(): Builder
    {
        // Custom scope for cleanup
        return static::query()
            ->where('created_at', '<', now()->subDays($this->getRetentionDays()))
            ->where('important', false);  // Keep important logs
    }
}
```

### Scheduled Cleanup

The package automatically schedules cleanup. Ensure your scheduler is running:

```php
// In app/Console/Kernel.php
protected function schedule(Schedule $schedule)
{
    $schedule->command('compliance:cleanup')->daily();
}
```

## Audit Logging

### Configuration

```php
'audit_logging' => [
    'enabled' => true,
    'log_reads' => false,
    'log_writes' => true,
    'log_deletions' => true,
    'log_exports' => true,
    'include_ip' => true,
    'include_user_agent' => true,
    'include_changes' => true,  // Log before/after values
],
```

### Automatic Model Auditing

Add the trait to models you want to audit:

```php
use ArtisanPackUI\Security\Concerns\Auditable;

class User extends Authenticatable
{
    use Auditable;

    // Specify which attributes to audit
    protected array $auditInclude = [
        'name', 'email', 'role_id',
    ];

    // Or exclude specific attributes
    protected array $auditExclude = [
        'password', 'remember_token',
    ];
}
```

### Manual Audit Logging

```php
use ArtisanPackUI\Security\Facades\AuditLog;

// Log a custom action
AuditLog::log('user.settings.updated', [
    'user_id' => $user->id,
    'changes' => ['timezone' => 'America/New_York'],
]);

// Log with specific severity
AuditLog::warning('suspicious.login', [
    'user_id' => $user->id,
    'ip_address' => request()->ip(),
    'reason' => 'Login from new country',
]);

// Log data access
AuditLog::access('user.data.viewed', [
    'viewer_id' => auth()->id(),
    'viewed_user_id' => $user->id,
]);
```

### Querying Audit Logs

```php
use ArtisanPackUI\Security\Models\AuditLog;

// Get all audit entries for a user
$logs = AuditLog::forUser($user)->get();

// Filter by action type
$logs = AuditLog::where('action', 'user.updated')
    ->recent()
    ->get();

// Filter by date range
$logs = AuditLog::whereBetween('created_at', [$start, $end])
    ->get();

// Get changes for a specific record
$logs = AuditLog::forModel($user)
    ->where('action', 'like', '%updated%')
    ->get();
```

### Audit Log Viewer

```blade
<livewire:audit-log-viewer :user="$user" />
```

Or query directly:

```php
// In a controller
public function auditLogs(User $user)
{
    $logs = AuditLog::forUser($user)
        ->with('causer')
        ->latest()
        ->paginate(50);

    return view('admin.audit-logs', compact('logs'));
}
```

## Compliance Reporting

### Generate Reports

```bash
# Generate GDPR compliance report
php artisan compliance:report gdpr

# Generate data retention report
php artisan compliance:report retention

# Generate consent report
php artisan compliance:report consent

# Generate audit summary
php artisan compliance:report audit --from="2024-01-01" --to="2024-12-31"

# Export to specific format
php artisan compliance:report gdpr --format=pdf --output=reports/
```

### Programmatic Reports

```php
use ArtisanPackUI\Security\Services\ComplianceReportService;

class ReportController extends Controller
{
    public function gdprReport(ComplianceReportService $reports)
    {
        $report = $reports->generateGdprReport([
            'period' => 'monthly',
            'include_metrics' => true,
        ]);

        return response()->json($report);
    }

    public function downloadReport(ComplianceReportService $reports)
    {
        $pdf = $reports->generateGdprReport([
            'format' => 'pdf',
        ]);

        return response()->download($pdf);
    }
}
```

### Report Contents

GDPR reports include:

- Data subject requests (access, erasure, portability)
- Consent statistics
- Data breaches (if any)
- Processing activities
- Third-party data sharing
- Retention compliance status

### Scheduled Reports

```php
// In app/Console/Kernel.php
$schedule->command('compliance:report gdpr --email=compliance@example.com')
    ->monthly();
```

## Data Processing Records

### Recording Processing Activities

```php
use ArtisanPackUI\Security\Services\ProcessingActivityService;

class NewsletterController extends Controller
{
    public function subscribe(
        Request $request,
        ProcessingActivityService $processing
    ) {
        // Record the processing activity
        $processing->record([
            'purpose' => 'newsletter_subscription',
            'legal_basis' => 'consent',
            'data_categories' => ['email', 'name'],
            'retention_period' => 'until_unsubscribe',
            'recipients' => ['mailchimp'],
        ]);

        // Process subscription...
    }
}
```

### Processing Activity Report

```bash
php artisan compliance:processing-activities
```

## Data Breach Management

### Recording a Breach

```php
use ArtisanPackUI\Security\Services\DataBreachService;

class SecurityController extends Controller
{
    public function reportBreach(Request $request, DataBreachService $breaches)
    {
        $breach = $breaches->record([
            'type' => 'unauthorized_access',
            'description' => 'Unauthorized access to user database',
            'affected_users' => 1500,
            'data_types' => ['email', 'name', 'hashed_password'],
            'discovered_at' => now(),
            'severity' => 'high',
        ]);

        // Automatically notifies DPO if configured
        // Generates incident report
        // Logs for compliance

        return response()->json(['breach_id' => $breach->id]);
    }
}
```

### Breach Notification

```php
'compliance' => [
    'breach_notification' => [
        'enabled' => true,
        'notify_dpo' => true,
        'dpo_email' => env('DPO_EMAIL'),
        'notify_authority_threshold' => 72,  // Hours to notify authority
        'notify_users' => true,
    ],
],
```

## Livewire Components

### Privacy Dashboard

```blade
<livewire:privacy-dashboard />
```

Features:
- View and download personal data
- Manage consent preferences
- Request account deletion
- View data processing information

### Consent Manager

```blade
<livewire:consent-manager />
```

Features:
- Update consent preferences
- View consent history
- Download consent receipts

### Admin Compliance Dashboard

```blade
<livewire:admin-compliance-dashboard />
```

Features:
- Compliance metrics overview
- Pending data requests
- Audit log summary
- Data retention status

## Events

| Event | Trigger |
|-------|---------|
| `DataExported` | User data export completed |
| `ErasureRequested` | User requested account deletion |
| `ErasureCompleted` | Account deletion completed |
| `ConsentUpdated` | User updated consent preferences |
| `DataBreachDetected` | Potential data breach identified |
| `RetentionCleanupCompleted` | Scheduled cleanup finished |

## Commands

```bash
# Run data retention cleanup
php artisan compliance:cleanup

# Generate compliance reports
php artisan compliance:report gdpr
php artisan compliance:report consent
php artisan compliance:report audit

# List processing activities
php artisan compliance:processing-activities

# Check compliance status
php artisan compliance:status

# Export user data (CLI)
php artisan compliance:export-user 1 --output=exports/

# Process pending erasure requests
php artisan compliance:process-erasures
```

## Best Practices

### 1. Document Processing Activities

Maintain records of all data processing:

```php
// Register processing activities at startup
ProcessingActivity::register([
    'name' => 'User Registration',
    'purpose' => 'Account creation and service provision',
    'legal_basis' => 'contract',
    'data_categories' => ['identity', 'contact'],
    'retention' => 'account_lifetime',
]);
```

### 2. Implement Privacy by Design

```php
// Collect only necessary data
$validated = $request->validate([
    'email' => 'required|email',
    'name' => 'required|string',
    // Don't collect unnecessary data
]);

// Pseudonymize where possible
$analyticsId = hash('sha256', $user->id . config('app.key'));
```

### 3. Regular Compliance Audits

```bash
# Schedule weekly compliance checks
php artisan compliance:audit --email=compliance@example.com
```

### 4. Train Staff

Document data handling procedures and ensure staff understands:
- What data is collected
- Why it's collected
- How long it's retained
- How to handle data requests

## International Compliance

### Multi-Region Support

```php
'compliance' => [
    'regions' => [
        'eu' => [
            'framework' => 'gdpr',
            'dpa' => 'Information Commissioner\'s Office',
        ],
        'california' => [
            'framework' => 'ccpa',
            'rights' => ['access', 'deletion', 'opt-out'],
        ],
    ],
],
```

### Region Detection

```php
use ArtisanPackUI\Security\Services\ComplianceService;

$compliance = app(ComplianceService::class);
$region = $compliance->detectUserRegion($request);
$requirements = $compliance->getRequirements($region);
```

## Related Documentation

- [Implementation Guide](implementation-guide.md)
- [Configuration Reference](configuration-reference.md)
- [Analytics & Monitoring](analytics-monitoring.md)
- [Troubleshooting Guide](troubleshooting.md)
