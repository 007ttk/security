# Security Event Logging Implementation Plan

## Overview

This document outlines the implementation plan for adding comprehensive security event logging to the ArtisanPack UI Security package. The feature will provide monitoring and audit capabilities for security-related events.

---

## Acceptance Criteria Checklist

- [ ] Create SecurityEventLogger service
- [ ] Log authentication events (login, logout, failed attempts)
- [ ] Log authorization failures
- [ ] Log security header violations
- [ ] Add configurable log levels
- [ ] Implement log retention policies
- [ ] Create security dashboard for events
- [ ] Add alerting for suspicious activities

---

## Architecture Overview

```
src/
├── Console/Commands/
│   ├── ClearSecurityEvents.php      # Retention policy command
│   ├── ExportSecurityEvents.php     # Export to CSV/JSON
│   └── ListSecurityEvents.php       # View recent events
├── Contracts/
│   └── SecurityEventLoggerInterface.php
├── Events/
│   ├── SecurityEventRecorded.php    # Dispatched after logging
│   └── SuspiciousActivityDetected.php
├── Http/
│   ├── Controllers/
│   │   └── SecurityExportController.php  # CSV/JSON export only
│   └── Middleware/
│       └── LogSecurityEvents.php
├── Listeners/
│   ├── LogAuthenticationEvents.php
│   ├── LogAuthorizationFailures.php
│   └── SendSuspiciousActivityAlert.php
├── Models/
│   └── SecurityEvent.php
├── Notifications/
│   └── SuspiciousActivityNotification.php
├── Services/
│   └── SecurityEventLogger.php
├── Livewire/
│   ├── SecurityDashboard.php
│   ├── SecurityEventList.php
│   └── SecurityStats.php
└── Views/
    └── livewire/
        ├── security-dashboard.blade.php
        ├── security-event-list.blade.php
        └── security-stats.blade.php

database/migrations/
└── create_security_events_table.php

config/security.php  # Add eventLogging section
```

---

## Implementation Steps

### Phase 1: Core Infrastructure

#### 1.1 Database Migration

**File:** `database/migrations/2025_XX_XX_XXXXXX_create_security_events_table.php`

| Column        | Type                         | Description                                          |
|---------------|------------------------------|------------------------------------------------------|
| `id`          | bigIncrements                | Primary key                                          |
| `event_type`  | string(50)                   | Event category (authentication, authorization, etc.) |
| `event_name`  | string(100)                  | Specific event (login_success, login_failed, etc.)   |
| `severity`    | enum                         | debug, info, warning, error, critical                |
| `user_id`     | unsignedBigInteger, nullable | Associated user                                      |
| `ip_address`  | string(45)                   | IPv4/IPv6 support                                    |
| `user_agent`  | text, nullable               | Browser/client info                                  |
| `url`         | string(2048), nullable       | Request URL                                          |
| `method`      | string(10), nullable         | HTTP method                                          |
| `status_code` | smallInteger, nullable       | HTTP response code                                   |
| `details`     | json, nullable               | Additional context                                   |
| `fingerprint` | string(64), nullable         | For grouping similar events                          |
| `created_at`  | timestamp                    | Event timestamp                                      |

**Indexes:**

- `event_type` - Filter by category
- `event_name` - Filter by specific event
- `severity` - Filter by severity level
- `user_id` - Filter by user
- `ip_address` - Filter by IP
- `created_at` - Time-based queries
- Composite: `(event_type, created_at)` - Common query pattern

#### 1.2 SecurityEvent Model

**File:** `src/Models/SecurityEvent.php`

```php
// Key features:
// - Fillable attributes for mass assignment
// - JSON casting for details column
// - Query scopes: byType(), byUser(), bySeverity(), recent(), suspicious()
// - Helper methods: isSuspicious(), getFormattedDetails()
// - No updated_at (append-only log)
```

**Query Scopes:**

- `scopeByType($query, string $type)` - Filter by event type
- `scopeByName($query, string $name)` - Filter by event name
- `scopeBySeverity($query, string $severity)` - Filter by severity
- `scopeByUser($query, int $userId)` - Filter by user
- `scopeByIp($query, string $ip)` - Filter by IP address
- `scopeRecent($query, int $hours = 24)` - Events within timeframe
- `scopeSuspicious($query)` - Flagged suspicious events
- `scopeInDateRange($query, $start, $end)` - Date range filter

#### 1.3 SecurityEventLogger Service

**File:** `src/Services/SecurityEventLogger.php`

**Public Methods:**

| Method                                                                         | Description            |
|--------------------------------------------------------------------------------|------------------------|
| `log(string $type, string $name, array $data = [], string $severity = 'info')` | Main logging method    |
| `authentication(string $event, array $data = [])`                              | Log auth events        |
| `authorization(string $event, array $data = [])`                               | Log authz events       |
| `apiAccess(string $event, array $data = [])`                                   | Log API events         |
| `securityViolation(string $event, array $data = [])`                           | Log violations         |
| `getRecentEvents(int $limit = 50)`                                             | Retrieve recent events |
| `getEventsByType(string $type, int $limit = 50)`                               | Filter by type         |
| `getEventStats(int $days = 7)`                                                 | Aggregate statistics   |
| `detectSuspiciousActivity()`                                                   | Analyze for anomalies  |
| `pruneOldEvents(int $days = null)`                                             | Retention cleanup      |

**Event Types:**

```php
const TYPE_AUTHENTICATION = 'authentication';
const TYPE_AUTHORIZATION = 'authorization';
const TYPE_API_ACCESS = 'api_access';
const TYPE_SECURITY_VIOLATION = 'security_violation';
const TYPE_ROLE_CHANGE = 'role_change';
const TYPE_PERMISSION_CHANGE = 'permission_change';
const TYPE_TOKEN_MANAGEMENT = 'token_management';
```

**Severity Levels:**

```php
const SEVERITY_DEBUG = 'debug';
const SEVERITY_INFO = 'info';
const SEVERITY_WARNING = 'warning';
const SEVERITY_ERROR = 'error';
const SEVERITY_CRITICAL = 'critical';
```

#### 1.4 Contract Interface

**File:** `src/Contracts/SecurityEventLoggerInterface.php`

Define the interface for the logger service to allow for custom implementations or mocking in tests.

---

### Phase 2: Configuration

#### 2.1 Configuration Structure

**File:** `config/security.php` (add new section)

```php
'eventLogging' => [
    // Master toggle
    'enabled' => env('SECURITY_EVENT_LOGGING_ENABLED', true),

    // Storage options
    'storage' => [
        'database' => env('SECURITY_EVENTS_STORE_DB', true),
        'logChannel' => env('SECURITY_LOG_CHANNEL', null), // null = default channel
    ],

    // Event types to log
    'events' => [
        'authentication' => [
            'enabled' => true,
            'logLevel' => 'info',
            'events' => [
                'loginSuccess' => true,
                'loginFailed' => true,
                'logout' => true,
                'passwordReset' => true,
                'twoFactorSuccess' => true,
                'twoFactorFailed' => true,
            ],
        ],
        'authorization' => [
            'enabled' => true,
            'logLevel' => 'warning',
            'events' => [
                'permissionDenied' => true,
                'roleCheckFailed' => true,
            ],
        ],
        'apiAccess' => [
            'enabled' => true,
            'logLevel' => 'info',
            'events' => [
                'tokenCreated' => true,
                'tokenRevoked' => true,
                'tokenExpiredAccess' => true,
                'invalidToken' => true,
                'abilityDenied' => true,
            ],
        ],
        'securityViolations' => [
            'enabled' => true,
            'logLevel' => 'error',
            'events' => [
                'cspViolation' => true,
                'rateLimitExceeded' => true,
                'invalidSignature' => true,
            ],
        ],
        'roleChanges' => [
            'enabled' => true,
            'logLevel' => 'info',
        ],
        'permissionChanges' => [
            'enabled' => true,
            'logLevel' => 'info',
        ],
    ],

    // Retention policy
    'retention' => [
        'enabled' => env('SECURITY_EVENTS_RETENTION_ENABLED', true),
        'days' => env('SECURITY_EVENTS_RETENTION_DAYS', 90),
        'keepCritical' => true, // Never delete critical severity events
    ],

    // Suspicious activity detection
    'suspiciousActivity' => [
        'enabled' => env('SECURITY_SUSPICIOUS_DETECTION_ENABLED', true),
        'thresholds' => [
            'failedLoginsPerIp' => 5,       // Per 15 minutes
            'failedLoginsPerUser' => 3,     // Per 15 minutes
            'apiErrorsPerToken' => 10,      // Per hour
            'permissionDenialsPerUser' => 5, // Per hour
        ],
        'windowMinutes' => 15,
    ],

    // Alerting
    'alerting' => [
        'enabled' => env('SECURITY_ALERTS_ENABLED', false),
        'channels' => ['mail'], // mail, slack, etc.
        'recipients' => env('SECURITY_ALERT_RECIPIENTS', ''),
        'throttleMinutes' => 15, // Don't spam alerts
    ],

    // Dashboard
    'dashboard' => [
        'enabled' => env('SECURITY_DASHBOARD_ENABLED', true),
        'routePrefix' => 'security',
        'middleware' => ['web', 'auth', 'permission:view-security-dashboard'],
    ],
],
```

---

### Phase 3: Event Logging Implementation

#### 3.1 Authentication Event Logging

**Integration Points:**

| Laravel Event                          | Security Event Name | Severity |
|----------------------------------------|---------------------|----------|
| `Illuminate\Auth\Events\Login`         | `login_success`     | info     |
| `Illuminate\Auth\Events\Failed`        | `login_failed`      | warning  |
| `Illuminate\Auth\Events\Logout`        | `logout`            | info     |
| `Illuminate\Auth\Events\PasswordReset` | `password_reset`    | info     |
| `Illuminate\Auth\Events\Lockout`       | `account_lockout`   | warning  |

**File:** `src/Listeners/LogAuthenticationEvents.php`

Register listeners in `SecurityServiceProvider::bootEventLogging()`:

```php
Event::listen(Login::class, [LogAuthenticationEvents::class, 'handleLogin']);
Event::listen(Failed::class, [LogAuthenticationEvents::class, 'handleFailed']);
Event::listen(Logout::class, [LogAuthenticationEvents::class, 'handleLogout']);
```

**Additional Data to Capture:**

- User ID and email
- IP address and user agent
- Remember me status
- Guard used
- Session ID (hashed)

#### 3.2 Authorization Failure Logging

**Integration Point:** Modify `CheckPermission` middleware

**File:** `src/Http/Middleware/CheckPermission.php` (modify)

Add logging before returning 401/403:

```php
if (Auth::guest()) {
    $this->logAuthorizationFailure('unauthenticated', $permission);
    abort(401);
}

if (!Auth::user()->can($permission)) {
    $this->logAuthorizationFailure('permission_denied', $permission);
    abort(403);
}
```

**Alternative:** Create dedicated listener for `Illuminate\Auth\Access\Events\GateEvaluated`

#### 3.3 API Access Logging

**Integration Points:**

| Middleware        | Events to Log                                                |
|-------------------|--------------------------------------------------------------|
| `ApiSecurity`     | token_validated, token_expired, token_revoked, invalid_token |
| `TokenAbility`    | ability_granted, ability_denied                              |
| `TokenAbilityAny` | ability_granted, ability_denied                              |

**Modify existing middleware** to inject logger and record events.

#### 3.4 Security Header Violation Logging

**New Endpoint:** CSP violation report URI

**File:** `src/Http/Controllers/CspReportController.php`

```php
// POST /security/csp-report
public function store(Request $request)
{
    $report = $request->input('csp-report');

    SecurityEventLogger::securityViolation('csp_violation', [
        'blocked_uri' => $report['blocked-uri'] ?? null,
        'violated_directive' => $report['violated-directive'] ?? null,
        'document_uri' => $report['document-uri'] ?? null,
        'original_policy' => $report['original-policy'] ?? null,
    ]);

    return response()->noContent();
}
```

**Configuration:** Add CSP report-uri to security headers config.

#### 3.5 Role & Permission Change Logging

**Integration:** Model observers or events

**File:** `src/Observers/RoleObserver.php`

```php
public function created(Role $role) { /* log role_created */ }
public function updated(Role $role) { /* log role_updated */ }
public function deleted(Role $role) { /* log role_deleted */ }
```

**File:** `src/Observers/PermissionObserver.php`

Same pattern for permissions.

**Pivot Table Changes:** Listen for sync events on role-permission and user-role relationships.

---

### Phase 4: Log Retention

#### 4.1 Retention Command

**File:** `src/Console/Commands/ClearSecurityEvents.php`

```php
protected $signature = 'security:clear-events
                        {--days= : Override retention days from config}
                        {--type= : Only clear specific event type}
                        {--keep-critical : Keep critical severity events}
                        {--dry-run : Show what would be deleted}';

protected $description = 'Clear old security events based on retention policy';
```

**Features:**

- Respects `retention.keepCritical` config
- Batch deletion for performance
- Progress bar for large datasets
- Dry-run mode
- Summary output

#### 4.2 Scheduled Task

**Documentation:** Add to README for users to schedule:

```php
// In app/Console/Kernel.php
$schedule->command('security:clear-events')->daily();
```

---

### Phase 5: Security Dashboard

#### 5.1 Package Dependency

Add `artisanpack-ui/livewire-ui-components` to `composer.json`:

```json
"require": {
    "artisanpack-ui/livewire-ui-components": "1.0.0-beta4"
}
```

This package provides pre-built Livewire UI components using DaisyUI styling. Components use the `x-artisanpack-*` prefix.

#### 5.2 Dashboard Routes

**File:** `routes/security.php`

| Method | URI | Component | Description |
|--------|-----|-----------|-------------|
| GET | `/security/dashboard` | `SecurityDashboard` | Main dashboard |
| GET | `/security/events` | `SecurityEventList` | Event list with filters |
| GET | `/security/events/export` | Controller method | Export to CSV/JSON |

#### 5.3 Livewire Components

**File:** `src/Livewire/SecurityDashboard.php`

Main dashboard component featuring:
- Uses `<x-artisanpack-stat>` for statistics display
- Uses `<x-artisanpack-card>` for content containers
- Uses `<x-artisanpack-chart>` for Chart.js visualizations
- Total events (24h, 7d, 30d)
- Events by type (pie chart)
- Events by severity (bar chart)
- Failed logins trend line chart
- Recent suspicious activity alerts
- Quick navigation to event list

**File:** `src/Livewire/SecurityEventList.php`

Event listing component featuring:
- Uses `<x-artisanpack-table>` with `:headers`, `:rows`, `with-pagination`
- Uses `<x-artisanpack-select>` for filter dropdowns
- Uses `<x-artisanpack-datepicker>` for date range filtering
- Uses `<x-artisanpack-input>` for search
- Uses `@scope` directives for custom cell rendering
- Real-time search with `wire:model.live.debounce`
- Sortable columns via `wire:model="sortBy"`
- Click row to view event details in modal

**File:** `src/Livewire/SecurityStats.php`

Statistics component featuring:
- Uses `<x-artisanpack-stat>` for metric display
- Uses `<x-artisanpack-table>` for top IPs/users lists
- Uses `<x-artisanpack-chart>` for event frequency line chart
- Configurable date range with `<x-artisanpack-datepicker>`

#### 5.4 Livewire Views

**File:** `views/livewire/security-dashboard.blade.php`

```blade
<div>
    <h1 class="text-2xl font-bold mb-6">Security Dashboard</h1>

    {{-- Statistics Cards --}}
    <div class="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
        <x-artisanpack-stat
            title="Events (24h)"
            :value="number_format($eventsToday)"
            description="{{ $eventsTodayChange }}% from yesterday"
            icon="heroicon-o-shield-check"
            color="text-primary"
        />
        <x-artisanpack-stat
            title="Failed Logins"
            :value="number_format($failedLogins)"
            icon="heroicon-o-x-circle"
            color="text-error"
        />
        <x-artisanpack-stat
            title="Auth Failures"
            :value="number_format($authFailures)"
            icon="heroicon-o-lock-closed"
            color="text-warning"
        />
        <x-artisanpack-stat
            title="API Errors"
            :value="number_format($apiErrors)"
            icon="heroicon-o-server"
            color="text-info"
        />
    </div>

    {{-- Charts --}}
    <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
        <x-artisanpack-card>
            <x-slot:header>
                <h3 class="text-lg font-bold">Events by Type</h3>
            </x-slot:header>
            <x-artisanpack-chart wire:model="eventsByTypeChart" class="h-64" />
        </x-artisanpack-card>

        <x-artisanpack-card>
            <x-slot:header>
                <h3 class="text-lg font-bold">Events by Severity</h3>
            </x-slot:header>
            <x-artisanpack-chart wire:model="eventsBySeverityChart" class="h-64" />
        </x-artisanpack-card>
    </div>

    {{-- Recent Suspicious Activity --}}
    <x-artisanpack-card>
        <x-slot:header>
            <h3 class="text-lg font-bold">Recent Suspicious Activity</h3>
        </x-slot:header>
        @forelse($suspiciousEvents as $event)
            <div class="flex items-center gap-4 p-2 border-b">
                <x-artisanpack-icon name="heroicon-o-exclamation-triangle" class="w-5 h-5 text-warning" />
                <span>{{ $event->details }}</span>
                <span class="text-sm text-gray-500">{{ $event->created_at->diffForHumans() }}</span>
            </div>
        @empty
            <p class="text-gray-500">No suspicious activity detected.</p>
        @endforelse
    </x-artisanpack-card>
</div>
```

**File:** `views/livewire/security-event-list.blade.php`

```blade
<div>
    <div class="flex justify-between items-center mb-6">
        <h1 class="text-2xl font-bold">Security Events</h1>
        <div class="flex gap-2">
            <x-artisanpack-button wire:click="export('csv')" color="primary" outline>
                Export CSV
            </x-artisanpack-button>
            <x-artisanpack-button wire:click="export('json')" color="primary" outline>
                Export JSON
            </x-artisanpack-button>
        </div>
    </div>

    {{-- Filters --}}
    <x-artisanpack-card class="mb-6">
        <div class="grid grid-cols-1 md:grid-cols-5 gap-4">
            <x-artisanpack-select
                label="Event Type"
                :options="$eventTypes"
                wire:model.live="filterType"
                placeholder="All Types"
            />
            <x-artisanpack-select
                label="Severity"
                :options="$severities"
                wire:model.live="filterSeverity"
                placeholder="All Severities"
            />
            <x-artisanpack-datepicker
                label="From Date"
                wire:model.live="filterFromDate"
            />
            <x-artisanpack-datepicker
                label="To Date"
                wire:model.live="filterToDate"
            />
            <x-artisanpack-input
                label="Search"
                wire:model.live.debounce.300ms="search"
                placeholder="Search events..."
            />
        </div>
    </x-artisanpack-card>

    {{-- Events Table --}}
    <x-artisanpack-card>
        <x-artisanpack-table
            :headers="$headers"
            :rows="$events"
            :sort-by="$sortBy"
            wire:model="sortBy"
            with-pagination
            per-page="perPage"
            :per-page-values="[10, 25, 50, 100]"
            striped
        >
            @scope('cell_severity', $event)
                <x-artisanpack-badge
                    :value="$event->severity"
                    class="{{ match($event->severity) {
                        'critical' => 'badge-error',
                        'error' => 'badge-error badge-outline',
                        'warning' => 'badge-warning',
                        'info' => 'badge-info',
                        default => 'badge-ghost'
                    } }}"
                />
            @endscope

            @scope('cell_created_at', $event)
                <span title="{{ $event->created_at }}">
                    {{ $event->created_at->diffForHumans() }}
                </span>
            @endscope

            @scope('actions', $event)
                <x-artisanpack-button
                    size="sm"
                    ghost
                    wire:click="showEvent({{ $event->id }})"
                >
                    <x-artisanpack-icon name="heroicon-o-eye" class="w-4 h-4" />
                </x-artisanpack-button>
            @endscope
        </x-artisanpack-table>
    </x-artisanpack-card>

    {{-- Event Detail Modal --}}
    <x-artisanpack-modal title="Event Details" id="eventDetailModal" width="max-w-2xl">
        @if($selectedEvent)
            <div class="space-y-4">
                <div class="grid grid-cols-2 gap-4">
                    <div>
                        <span class="text-gray-500">Event Type:</span>
                        <span class="font-semibold">{{ $selectedEvent->event_type }}</span>
                    </div>
                    <div>
                        <span class="text-gray-500">Event Name:</span>
                        <span class="font-semibold">{{ $selectedEvent->event_name }}</span>
                    </div>
                    <div>
                        <span class="text-gray-500">Severity:</span>
                        <span class="font-semibold">{{ $selectedEvent->severity }}</span>
                    </div>
                    <div>
                        <span class="text-gray-500">Timestamp:</span>
                        <span class="font-semibold">{{ $selectedEvent->created_at }}</span>
                    </div>
                    <div>
                        <span class="text-gray-500">IP Address:</span>
                        <span class="font-semibold">{{ $selectedEvent->ip_address }}</span>
                    </div>
                    <div>
                        <span class="text-gray-500">User:</span>
                        <span class="font-semibold">{{ $selectedEvent->user?->email ?? 'N/A' }}</span>
                    </div>
                </div>
                @if($selectedEvent->details)
                    <div>
                        <span class="text-gray-500">Details:</span>
                        <pre class="mt-2 p-4 bg-base-200 rounded text-sm overflow-x-auto">{{ json_encode($selectedEvent->details, JSON_PRETTY_PRINT) }}</pre>
                    </div>
                @endif
            </div>
        @endif
        <x-slot:footer>
            <x-artisanpack-button @click="$refs.eventDetailModal.close()">Close</x-artisanpack-button>
        </x-slot:footer>
    </x-artisanpack-modal>
</div>
```

**File:** `views/livewire/security-stats.blade.php`

```blade
<div>
    <div class="flex justify-between items-center mb-6">
        <h1 class="text-2xl font-bold">Security Statistics</h1>
        <x-artisanpack-datepicker
            wire:model.live="dateRange"
            :config="['mode' => 'range']"
            placeholder="Select date range"
        />
    </div>

    <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
        {{-- Top IPs --}}
        <x-artisanpack-card>
            <x-slot:header>
                <h3 class="text-lg font-bold">Top IPs by Failed Attempts</h3>
            </x-slot:header>
            <x-artisanpack-table :headers="$ipHeaders" :rows="$topIps" />
        </x-artisanpack-card>

        {{-- Top Users --}}
        <x-artisanpack-card>
            <x-slot:header>
                <h3 class="text-lg font-bold">Top Users by Permission Denials</h3>
            </x-slot:header>
            <x-artisanpack-table :headers="$userHeaders" :rows="$topUsers" />
        </x-artisanpack-card>
    </div>

    {{-- Event Frequency Chart --}}
    <x-artisanpack-card>
        <x-slot:header>
            <h3 class="text-lg font-bold">Event Frequency Over Time</h3>
        </x-slot:header>
        <x-artisanpack-chart wire:model="eventFrequencyChart" class="h-64" />
    </x-artisanpack-card>
</div>
```

#### 5.5 Chart Data Structure

The `<x-artisanpack-chart>` component requires Chart.js configuration format:

```php
// In Livewire component
public array $eventsByTypeChart = [];

public function mount(): void
{
    $this->eventsByTypeChart = [
        'type' => 'pie',
        'data' => [
            'labels' => ['Authentication', 'Authorization', 'API Access', 'Security Violations'],
            'datasets' => [
                [
                    'data' => [120, 45, 89, 12],
                    'backgroundColor' => [
                        'rgba(59, 130, 246, 0.5)',  // blue
                        'rgba(245, 158, 11, 0.5)',  // amber
                        'rgba(16, 185, 129, 0.5)',  // green
                        'rgba(239, 68, 68, 0.5)',   // red
                    ],
                ],
            ],
        ],
    ];
}
```

#### 5.6 Component Registration

Register Livewire components in service provider:

```php
use Livewire\Livewire;

protected function bootEventLogging(): void
{
    // ... existing code ...

    // Register Livewire components
    if (config('artisanpack.security.eventLogging.dashboard.enabled')) {
        Livewire::component('security-dashboard', SecurityDashboard::class);
        Livewire::component('security-event-list', SecurityEventList::class);
        Livewire::component('security-stats', SecurityStats::class);
    }
}

---

### Phase 6: Suspicious Activity Detection & Alerting

#### 6.1 Detection Logic

**File:** `src/Services/SecurityEventLogger.php` (add method)

```php
public function detectSuspiciousActivity(): Collection
{
    $suspicious = collect();
    $window = config('artisanpack.security.eventLogging.suspiciousActivity.windowMinutes');
    $thresholds = config('artisanpack.security.eventLogging.suspiciousActivity.thresholds');

    // Check failed logins per IP
    $failedByIp = SecurityEvent::where('event_name', 'login_failed')
        ->where('created_at', '>=', now()->subMinutes($window))
        ->selectRaw('ip_address, COUNT(*) as count')
        ->groupBy('ip_address')
        ->having('count', '>=', $thresholds['failedLoginsPerIp'])
        ->get();

    // ... similar checks for other thresholds

    return $suspicious;
}
```

#### 6.2 Alert Notification

**File:** `src/Notifications/SuspiciousActivityNotification.php`

```php
class SuspiciousActivityNotification extends Notification
{
    public function via($notifiable): array
    {
        return config('artisanpack.security.eventLogging.alerting.channels');
    }

    public function toMail($notifiable): MailMessage
    {
        return (new MailMessage)
            ->subject('Security Alert: Suspicious Activity Detected')
            ->line('Suspicious activity has been detected on your application.')
            ->line("Type: {$this->activity['type']}")
            ->line("Details: {$this->activity['details']}")
            ->action('View Dashboard', url('/security/dashboard'));
    }
}
```

#### 6.3 Alert Throttling

Prevent alert spam by tracking last alert time per activity type:

- Use cache to store last alert timestamp
- Check throttle window before sending
- Group similar alerts into single notification

#### 6.4 Scheduled Detection

**Command:** `src/Console/Commands/DetectSuspiciousActivity.php`

```php
protected $signature = 'security:detect-suspicious';
protected $description = 'Analyze recent events for suspicious activity patterns';
```

Schedule to run every 5-15 minutes.

---

### Phase 7: Console Commands

#### 7.1 List Events Command

**File:** `src/Console/Commands/ListSecurityEvents.php`

```php
protected $signature = 'security:events
                        {--type= : Filter by event type}
                        {--severity= : Filter by severity}
                        {--user= : Filter by user ID}
                        {--ip= : Filter by IP address}
                        {--since= : Events since (e.g., "1 hour ago")}
                        {--limit=50 : Number of events to show}';

protected $description = 'List recent security events';
```

**Output:** Table with columns: Time, Type, Event, Severity, User, IP

#### 7.2 Export Events Command

**File:** `src/Console/Commands/ExportSecurityEvents.php`

```php
protected $signature = 'security:export
                        {--format=csv : Export format (csv, json)}
                        {--output= : Output file path}
                        {--since= : Events since date}
                        {--until= : Events until date}
                        {--type= : Filter by event type}';

protected $description = 'Export security events to file';
```

#### 7.3 Stats Command

**File:** `src/Console/Commands/SecurityStats.php`

```php
protected $signature = 'security:stats {--days=7 : Number of days to analyze}';
protected $description = 'Display security event statistics';
```

**Output:**

- Total events by type
- Events by severity
- Top 10 IPs by event count
- Top 10 users by event count
- Failed authentication attempts
- Authorization failures

---

### Phase 8: Service Provider Integration

#### 8.1 New Boot Method

**File:** `src/SecurityServiceProvider.php` (modify)

```php
protected function bootEventLogging(): void
{
    if (!config('artisanpack.security.eventLogging.enabled')) {
        return;
    }

    // Load migrations
    $this->loadMigrationsFrom(__DIR__ . '/../database/migrations');

    // Register event listeners
    $this->registerSecurityEventListeners();

    // Register model observers
    $this->registerSecurityObservers();

    // Register routes (dashboard)
    if (config('artisanpack.security.eventLogging.dashboard.enabled')) {
        $this->registerDashboardRoutes();
    }

    // Register commands
    if ($this->app->runningInConsole()) {
        $this->commands([
            ListSecurityEvents::class,
            ClearSecurityEvents::class,
            ExportSecurityEvents::class,
            SecurityStats::class,
            DetectSuspiciousActivity::class,
        ]);
    }
}
```

#### 8.2 Service Registration

```php
public function register(): void
{
    // ... existing code ...

    $this->app->singleton(SecurityEventLoggerInterface::class, function ($app) {
        return new SecurityEventLogger();
    });

    $this->app->alias(SecurityEventLoggerInterface::class, 'security-events');
}
```

#### 8.3 Facade (Optional)

**File:** `src/Facades/SecurityEvents.php`

```php
class SecurityEvents extends Facade
{
    protected static function getFacadeAccessor()
    {
        return 'security-events';
    }
}
```

---

### Phase 9: Testing

#### 9.1 Unit Tests

**File:** `tests/Unit/SecurityEventLoggerTest.php`

| Test                             | Description          |
|----------------------------------|----------------------|
| `it_logs_event_to_database`      | Verify DB storage    |
| `it_logs_event_to_channel`       | Verify log channel   |
| `it_respects_enabled_config`     | Skip when disabled   |
| `it_respects_event_type_config`  | Skip disabled types  |
| `it_captures_request_context`    | IP, UA, URL captured |
| `it_detects_suspicious_activity` | Threshold detection  |
| `it_prunes_old_events`           | Retention policy     |
| `it_keeps_critical_events`       | Critical retention   |

#### 9.2 Feature Tests

**File:** `tests/Feature/SecurityEventLoggingTest.php`

| Test                         | Description            |
|------------------------------|------------------------|
| `it_logs_successful_login`   | Auth event logging     |
| `it_logs_failed_login`       | Failed auth logging    |
| `it_logs_logout`             | Logout event           |
| `it_logs_permission_denied`  | Authorization failure  |
| `it_logs_api_token_events`   | Token lifecycle        |
| `it_logs_role_changes`       | Role CRUD events       |
| `it_logs_permission_changes` | Permission CRUD events |

**File:** `tests/Feature/SecurityDashboardTest.php`

| Test                                    | Description                     |
|-----------------------------------------|---------------------------------|
| `it_requires_authentication`            | Auth middleware                 |
| `it_requires_permission`                | Permission check                |
| `it_displays_dashboard_stats`           | Livewire component renders      |
| `it_displays_events_by_type_chart`      | Chart data renders correctly    |
| `it_filters_events_by_type`             | Livewire filter functionality   |
| `it_filters_events_by_severity`         | Livewire filter functionality   |
| `it_filters_events_by_date_range`       | Livewire date range filter      |
| `it_paginates_event_list`               | Livewire pagination             |
| `it_sorts_events_by_column`             | Livewire sortable columns       |
| `it_searches_events`                    | Livewire search functionality   |
| `it_exports_to_csv`                     | CSV export                      |
| `it_exports_to_json`                    | JSON export                     |
| `it_shows_event_detail_modal`           | Livewire modal interaction      |

**File:** `tests/Feature/SecurityEventCommandsTest.php`

| Test                       | Description    |
|----------------------------|----------------|
| `it_lists_security_events` | List command   |
| `it_clears_old_events`     | Clear command  |
| `it_exports_events`        | Export command |
| `it_shows_statistics`      | Stats command  |

---

## File Creation Order

Based on dependencies, create files in this order:

1. **Migration** - `create_security_events_table.php`
2. **Model** - `SecurityEvent.php`
3. **Contract** - `SecurityEventLoggerInterface.php`
4. **Service** - `SecurityEventLogger.php`
5. **Configuration** - Update `config/security.php`
6. **Listeners** - `LogAuthenticationEvents.php`, etc.
7. **Observers** - `RoleObserver.php`, `PermissionObserver.php`
8. **Middleware modifications** - Update `CheckPermission.php`, `ApiSecurity.php`
9. **Commands** - All console commands
10. **Notification** - `SuspiciousActivityNotification.php`
11. **Livewire Components** - `SecurityDashboard.php`, `SecurityEventList.php`, `SecurityStats.php`
12. **Livewire Views** - Dashboard Blade templates using `artisanpack-ui/livewire-ui-components`
13. **Routes** - Dashboard routes file
14. **Service Provider** - Update `SecurityServiceProvider.php`
15. **Tests** - Unit and Feature tests

---

## Performance Considerations

1. **Async Logging:** Consider using queued jobs for non-critical events
2. **Batch Inserts:** For high-traffic apps, buffer events and batch insert
3. **Index Strategy:** Only index columns used in WHERE clauses
4. **Partition Tables:** For very large datasets, consider date-based partitioning
5. **Retention:** Aggressive pruning for debug/info level events
6. **Caching:** Cache dashboard statistics with short TTL

---

## Security Considerations

1. **PII Handling:** Hash or mask sensitive data in logs
2. **Access Control:** Dashboard requires specific permission
3. **Log Injection:** Sanitize user-controlled data before logging
4. **Rate Limiting:** Prevent log flooding attacks
5. **Encryption:** Consider encrypting sensitive details column

---

## Documentation Updates

After implementation, update:

1. **README.md** - Feature overview and quick start
2. **CHANGELOG.md** - New feature entry
3. **Configuration docs** - All new config options
4. **API docs** - Dashboard routes and service methods

---

## Estimated Scope

| Phase                        | Files | Complexity |
|------------------------------|-------|------------|
| Phase 1: Core Infrastructure | 4     | Medium     |
| Phase 2: Configuration       | 1     | Low        |
| Phase 3: Event Logging       | 6     | Medium     |
| Phase 4: Log Retention       | 1     | Low        |
| Phase 5: Security Dashboard  | 6     | High       |
| Phase 6: Suspicious Activity | 3     | Medium     |
| Phase 7: Console Commands    | 4     | Low        |
| Phase 8: Service Provider    | 1     | Medium     |
| Phase 9: Testing             | 4     | Medium     |

**Total new files:** ~30 files
