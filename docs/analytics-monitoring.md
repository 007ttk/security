---
title: Analytics & Monitoring Guide
---

# Analytics & Monitoring Guide

This guide covers the security analytics and monitoring features including dashboards, metrics collection, alerting, threat detection, and reporting.

## Overview

The ArtisanPack Security package provides comprehensive analytics and monitoring:

- **Security Dashboard**: Real-time overview of security metrics
- **Metrics Collection**: Track authentication, authorization, and security events
- **Alerting System**: Configure alerts for security incidents
- **Threat Detection**: Identify suspicious patterns and potential attacks
- **Reporting**: Generate security reports and analytics

## Configuration

Configure analytics and monitoring in `config/artisanpack/security.php`:

```php
'analytics' => [
    'enabled' => env('SECURITY_ANALYTICS_ENABLED', true),

    'metrics' => [
        'enabled' => true,
        'driver' => 'database',         // 'database', 'redis', 'prometheus'
        'retention_days' => 90,
        'sample_rate' => 1.0,           // 1.0 = 100% of events

        'collect' => [
            'authentication' => true,
            'authorization' => true,
            'api_requests' => true,
            'security_events' => true,
            'performance' => true,
        ],
    ],

    'dashboard' => [
        'enabled' => true,
        'refresh_interval' => 60,       // Seconds
        'default_period' => '7d',       // Default time range
    ],

    'alerts' => [
        'enabled' => true,
        'channels' => ['database', 'mail'],
        'throttle_minutes' => 15,       // Prevent alert flooding

        'thresholds' => [
            'failed_logins_per_hour' => 50,
            'blocked_requests_per_hour' => 100,
            'suspicious_activities_per_day' => 10,
            'new_devices_per_user_per_day' => 3,
        ],
    ],

    'threat_detection' => [
        'enabled' => true,
        'rules' => [
            'brute_force' => true,
            'credential_stuffing' => true,
            'session_hijacking' => true,
            'privilege_escalation' => true,
            'data_exfiltration' => true,
        ],
    ],
],
```

## Security Dashboard

### Admin Dashboard Route

```php
Route::middleware(['auth', 'permission:view-security-dashboard'])
    ->prefix('admin/security')
    ->group(function () {
        Route::get('/dashboard', [SecurityDashboardController::class, 'index'])
            ->name('security.dashboard');
    });
```

### Livewire Dashboard Component

```blade
<livewire:security-dashboard />
```

The dashboard displays:

- Authentication metrics (logins, failures, 2FA usage)
- Active sessions overview
- Recent security events
- Threat detection alerts
- API usage statistics
- Geographic login distribution

### Custom Dashboard

```php
use ArtisanPackUI\Security\Services\SecurityAnalyticsService;

class SecurityDashboardController extends Controller
{
    public function index(SecurityAnalyticsService $analytics)
    {
        return view('admin.security.dashboard', [
            'authMetrics' => $analytics->getAuthenticationMetrics('24h'),
            'securityEvents' => $analytics->getRecentSecurityEvents(20),
            'activeThreats' => $analytics->getActiveThreats(),
            'apiMetrics' => $analytics->getApiMetrics('24h'),
            'topCountries' => $analytics->getLoginsByCountry('7d'),
        ]);
    }
}
```

## Metrics Collection

### Authentication Metrics

```php
use ArtisanPackUI\Security\Services\SecurityMetricsService;

$metrics = app(SecurityMetricsService::class);

// Get authentication statistics
$authStats = $metrics->getAuthenticationStats('24h');
// Returns:
// [
//     'total_logins' => 1250,
//     'successful_logins' => 1180,
//     'failed_logins' => 70,
//     'unique_users' => 890,
//     'two_factor_challenges' => 450,
//     'two_factor_success_rate' => 0.98,
//     'average_login_time' => 2.3,  // seconds
// ]

// Get login failure breakdown
$failures = $metrics->getLoginFailures('24h');
// Returns:
// [
//     'invalid_credentials' => 45,
//     'account_locked' => 12,
//     'two_factor_failed' => 8,
//     'expired_password' => 5,
// ]
```

### Session Metrics

```php
// Get session statistics
$sessionStats = $metrics->getSessionStats();
// Returns:
// [
//     'active_sessions' => 2340,
//     'average_session_duration' => 45.2,  // minutes
//     'sessions_per_user' => 1.8,
//     'terminated_sessions_24h' => 120,
// ]

// Get concurrent session distribution
$concurrent = $metrics->getConcurrentSessionDistribution();
// Returns:
// [
//     '1' => 1500,   // Users with 1 session
//     '2' => 450,    // Users with 2 sessions
//     '3' => 200,    // Users with 3 sessions
//     '4+' => 100,
// ]
```

### API Metrics

```php
// Get API usage statistics
$apiStats = $metrics->getApiStats('24h');
// Returns:
// [
//     'total_requests' => 45000,
//     'unique_tokens' => 120,
//     'average_response_time' => 145,  // ms
//     'error_rate' => 0.02,
//     'rate_limited_requests' => 350,
// ]

// Get API endpoint breakdown
$endpoints = $metrics->getApiEndpointStats('24h');
// Returns array of endpoint statistics
```

### Security Event Metrics

```php
// Get security event summary
$events = $metrics->getSecurityEventSummary('7d');
// Returns:
// [
//     'total_events' => 850,
//     'by_severity' => [
//         'critical' => 5,
//         'high' => 25,
//         'medium' => 120,
//         'low' => 700,
//     ],
//     'by_type' => [
//         'authentication' => 400,
//         'authorization' => 200,
//         'suspicious_activity' => 150,
//         'configuration' => 100,
//     ],
// ]
```

## Alerting System

### Configuration

```php
'alerts' => [
    'enabled' => true,
    'channels' => ['database', 'mail', 'slack'],

    'recipients' => [
        'mail' => ['security@example.com'],
        'slack' => env('SLACK_SECURITY_WEBHOOK'),
    ],

    'thresholds' => [
        'failed_logins_per_hour' => 50,
        'blocked_requests_per_hour' => 100,
        'suspicious_activities_per_day' => 10,
        'new_devices_per_user_per_day' => 3,
        'api_error_rate' => 0.05,           // 5%
        'brute_force_attempts' => 10,
    ],
],
```

### Alert Types

| Alert Type | Trigger | Default Threshold |
|------------|---------|-------------------|
| `brute_force_detected` | Multiple failed logins from same IP | 10 attempts |
| `account_lockout_spike` | Unusual number of lockouts | 20/hour |
| `suspicious_login` | Login from new location/device | Configurable |
| `privilege_escalation` | Unauthorized permission change | Any occurrence |
| `api_abuse` | Excessive API errors or rate limits | 5% error rate |
| `session_anomaly` | Session hijacking indicators | Any detection |

### Custom Alerts

```php
use ArtisanPackUI\Security\Services\SecurityAlertService;
use ArtisanPackUI\Security\Alerts\SecurityAlert;

class CustomSecurityMonitor
{
    public function __construct(
        private SecurityAlertService $alerts
    ) {}

    public function checkForAnomalies(): void
    {
        $unusualActivity = $this->detectUnusualActivity();

        if ($unusualActivity) {
            $this->alerts->trigger(new SecurityAlert(
                type: 'custom_anomaly',
                severity: 'high',
                title: 'Unusual Activity Detected',
                message: 'Detected unusual pattern in user behavior.',
                context: [
                    'user_id' => $unusualActivity->user_id,
                    'pattern' => $unusualActivity->pattern,
                    'timestamp' => now()->toIso8601String(),
                ],
            ));
        }
    }
}
```

### Alert Channels

#### Email Alerts

```php
'alerts' => [
    'channels' => ['mail'],
    'mail' => [
        'recipients' => ['security@example.com', 'admin@example.com'],
        'from' => 'alerts@example.com',
    ],
],
```

#### Slack Alerts

```php
'alerts' => [
    'channels' => ['slack'],
    'slack' => [
        'webhook_url' => env('SLACK_SECURITY_WEBHOOK'),
        'channel' => '#security-alerts',
        'mention_on_critical' => '@security-team',
    ],
],
```

#### Custom Alert Channel

```php
use ArtisanPackUI\Security\Contracts\AlertChannelInterface;

class PagerDutyChannel implements AlertChannelInterface
{
    public function send(SecurityAlert $alert): void
    {
        // Send to PagerDuty API
        Http::post('https://events.pagerduty.com/v2/enqueue', [
            'routing_key' => config('services.pagerduty.key'),
            'event_action' => 'trigger',
            'payload' => [
                'summary' => $alert->title,
                'severity' => $this->mapSeverity($alert->severity),
                'source' => config('app.name'),
                'custom_details' => $alert->context,
            ],
        ]);
    }
}

// Register in a service provider
$this->app->bind('security.alert.pagerduty', PagerDutyChannel::class);
```

### Managing Alerts

```php
use ArtisanPackUI\Security\Models\SecurityAlert;

// Get unacknowledged alerts
$alerts = SecurityAlert::unacknowledged()
    ->orderBy('severity')
    ->orderBy('created_at', 'desc')
    ->get();

// Acknowledge an alert
$alert->acknowledge(auth()->user(), 'Investigating');

// Resolve an alert
$alert->resolve(auth()->user(), 'False positive - automated testing');

// Get alert history
$history = SecurityAlert::where('created_at', '>=', now()->subDays(30))
    ->with('acknowledgedBy', 'resolvedBy')
    ->get();
```

## Threat Detection

### Configuration

```php
'threat_detection' => [
    'enabled' => true,

    'rules' => [
        'brute_force' => [
            'enabled' => true,
            'threshold' => 10,          // Attempts
            'window_minutes' => 15,
            'action' => 'block_ip',     // 'alert', 'block_ip', 'lock_account'
        ],

        'credential_stuffing' => [
            'enabled' => true,
            'threshold' => 50,          // Unique usernames
            'window_minutes' => 60,
            'action' => 'block_ip',
        ],

        'session_hijacking' => [
            'enabled' => true,
            'detect_ip_change' => true,
            'detect_ua_change' => true,
            'action' => 'terminate_session',
        ],

        'privilege_escalation' => [
            'enabled' => true,
            'action' => 'alert',
        ],

        'data_exfiltration' => [
            'enabled' => true,
            'threshold_records' => 1000,    // Records per request
            'threshold_requests' => 100,    // Bulk requests per hour
            'action' => 'alert',
        ],
    ],
],
```

### Threat Detection Service

```php
use ArtisanPackUI\Security\Services\ThreatDetectionService;

class SecurityMiddleware
{
    public function __construct(
        private ThreatDetectionService $threats
    ) {}

    public function handle($request, $next)
    {
        // Analyze request for threats
        $analysis = $this->threats->analyzeRequest($request);

        if ($analysis->hasThreat()) {
            Log::warning('Threat detected', [
                'type' => $analysis->threatType,
                'severity' => $analysis->severity,
                'ip' => $request->ip(),
            ]);

            if ($analysis->shouldBlock()) {
                abort(403, 'Access denied');
            }
        }

        return $next($request);
    }
}
```

### Custom Threat Rules

```php
use ArtisanPackUI\Security\Contracts\ThreatRuleInterface;
use ArtisanPackUI\Security\Threats\ThreatAnalysis;

class CustomThreatRule implements ThreatRuleInterface
{
    public function analyze($request, $context): ThreatAnalysis
    {
        // Custom threat detection logic
        $suspicious = $this->checkForSuspiciousPattern($request);

        if ($suspicious) {
            return new ThreatAnalysis(
                detected: true,
                type: 'custom_threat',
                severity: 'medium',
                confidence: 0.85,
                action: 'alert',
                details: ['pattern' => $suspicious],
            );
        }

        return ThreatAnalysis::safe();
    }

    public function getName(): string
    {
        return 'custom_threat_rule';
    }
}

// Register the rule
ThreatDetection::registerRule(new CustomThreatRule());
```

### IP Reputation

```php
use ArtisanPackUI\Security\Services\IpReputationService;

$reputation = app(IpReputationService::class);

// Check IP reputation
$score = $reputation->getScore($request->ip());
// Returns 0-100 (100 = trusted, 0 = malicious)

// Check against known bad IPs
if ($reputation->isBlacklisted($request->ip())) {
    abort(403);
}

// Get IP details
$details = $reputation->getDetails($request->ip());
// Returns: ['country', 'isp', 'is_proxy', 'is_tor', 'threat_types']
```

## Real-Time Monitoring

### WebSocket Events

```php
// In your JavaScript
import Echo from 'laravel-echo';

Echo.private('security.dashboard')
    .listen('SecurityEventOccurred', (e) => {
        console.log('Security event:', e);
        updateDashboard(e);
    })
    .listen('ThreatDetected', (e) => {
        console.log('Threat detected:', e);
        showAlert(e);
    });
```

### Live Metrics

```php
use ArtisanPackUI\Security\Services\RealTimeMetricsService;

class LiveDashboardController extends Controller
{
    public function metrics(RealTimeMetricsService $realtime)
    {
        return response()->json([
            'active_users' => $realtime->getActiveUsers(),
            'requests_per_second' => $realtime->getRequestsPerSecond(),
            'active_threats' => $realtime->getActiveThreats(),
            'recent_events' => $realtime->getRecentEvents(10),
        ]);
    }
}
```

## Reporting

### Generate Reports

```bash
# Generate security summary report
php artisan security:report summary --period=30d

# Generate authentication report
php artisan security:report authentication --from="2024-01-01" --to="2024-01-31"

# Generate threat report
php artisan security:report threats --period=7d --format=pdf

# Generate API usage report
php artisan security:report api --period=30d --format=csv

# Email report to stakeholders
php artisan security:report summary --period=30d --email=security@example.com
```

### Programmatic Reports

```php
use ArtisanPackUI\Security\Services\SecurityReportService;

class ReportController extends Controller
{
    public function securitySummary(SecurityReportService $reports)
    {
        $report = $reports->generateSummary([
            'period' => '30d',
            'include' => [
                'authentication',
                'threats',
                'api_usage',
                'compliance',
            ],
        ]);

        return view('admin.reports.security', compact('report'));
    }

    public function downloadReport(SecurityReportService $reports, string $type)
    {
        $pdf = $reports->generate($type, [
            'period' => request('period', '30d'),
            'format' => 'pdf',
        ]);

        return response()->download($pdf);
    }
}
```

### Scheduled Reports

```php
// In app/Console/Kernel.php
protected function schedule(Schedule $schedule)
{
    // Weekly security summary
    $schedule->command('security:report summary --email=security@example.com')
        ->weekly()
        ->mondays()
        ->at('08:00');

    // Daily threat report
    $schedule->command('security:report threats --email=security@example.com')
        ->daily()
        ->at('06:00');
}
```

### Report Contents

Security Summary Report includes:

- Executive summary
- Authentication metrics and trends
- Security incidents and resolutions
- Threat detection statistics
- API usage patterns
- Compliance status
- Recommendations

## Geographic Analytics

### Login Geography

```php
use ArtisanPackUI\Security\Services\GeoAnalyticsService;

$geo = app(GeoAnalyticsService::class);

// Get logins by country
$countries = $geo->getLoginsByCountry('30d');

// Get logins by city
$cities = $geo->getLoginsByCity('30d');

// Detect anomalous locations
$anomalies = $geo->detectLocationAnomalies($user);
```

### Geo-Visualization Data

```php
public function geoData(GeoAnalyticsService $geo)
{
    return response()->json([
        'countries' => $geo->getLoginsByCountry('7d'),
        'heatmap' => $geo->getLoginHeatmap('7d'),
        'anomalies' => $geo->getRecentAnomalies(),
    ]);
}
```

## Performance Monitoring

### Security Performance Metrics

```php
use ArtisanPackUI\Security\Services\PerformanceMetricsService;

$perf = app(PerformanceMetricsService::class);

// Get middleware performance
$middlewareStats = $perf->getMiddlewareStats();
// Returns average execution time per middleware

// Get authentication performance
$authPerf = $perf->getAuthenticationPerformance();
// Returns login/2FA verification times

// Get API performance by security level
$apiPerf = $perf->getApiPerformanceBySecurity();
```

## Events

| Event | Trigger |
|-------|---------|
| `SecurityMetricsCollected` | Metrics batch collected |
| `SecurityAlertTriggered` | Alert threshold exceeded |
| `ThreatDetected` | Threat rule matched |
| `ThreatMitigated` | Threat automatically blocked |
| `SecurityReportGenerated` | Report completed |

## Commands

```bash
# View real-time security metrics
php artisan security:metrics

# Check current threat status
php artisan security:threats

# List active alerts
php artisan security:alerts

# Acknowledge an alert
php artisan security:alerts --acknowledge=123

# Generate security report
php artisan security:report summary

# Clean old metrics data
php artisan security:metrics-cleanup --days=90

# Test alert channels
php artisan security:test-alerts
```

## Livewire Components

### Security Dashboard

```blade
<livewire:security-dashboard />
```

### Alert Manager

```blade
<livewire:security-alert-manager />
```

### Real-Time Metrics

```blade
<livewire:realtime-security-metrics :refresh-interval="5" />
```

### Threat Map

```blade
<livewire:security-threat-map />
```

## Best Practices

### 1. Set Appropriate Thresholds

Start with conservative thresholds and adjust based on your application's normal traffic:

```php
'thresholds' => [
    'failed_logins_per_hour' => 50,  // Adjust based on user base
],
```

### 2. Use Multiple Alert Channels

```php
'channels' => ['database', 'mail', 'slack'],
```

### 3. Regular Review

Schedule weekly review of:
- Unacknowledged alerts
- Threat detection accuracy
- False positive rates

### 4. Retain Sufficient History

```php
'retention_days' => 90,  // Keep 90 days for trend analysis
```

### 5. Monitor Monitor

Set up external monitoring for your security monitoring system:

```php
// Health check endpoint
Route::get('/health/security', function () {
    return response()->json([
        'metrics_collecting' => true,
        'alerts_functional' => true,
        'last_collection' => cache('security_last_collection'),
    ]);
});
```

## Related Documentation

- [Implementation Guide](implementation-guide.md)
- [Configuration Reference](configuration-reference.md)
- [Compliance Framework](compliance-framework.md)
- [Troubleshooting Guide](troubleshooting.md)
