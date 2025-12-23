# Content Security Policy (CSP) Framework Implementation Plan

Implementation of dynamic Content Security Policy generation specifically optimized for Livewire applications for the ArtisanPackUI Security package.

## Overview

This plan outlines the implementation of a comprehensive CSP framework that generates dynamic, per-request Content Security Policies with proper nonce support for Livewire and Alpine.js applications. The framework will eliminate the need for `'unsafe-inline'` and `'unsafe-eval'` directives while maintaining full Livewire compatibility.

## Current State Analysis

### Existing Implementation
- Static CSP header defined in `config/artisanpack/security.php` (lines 73-107)
- `SecurityHeadersMiddleware` applies headers from config to all responses
- Current CSP uses `'unsafe-inline'` and `'unsafe-eval'` for Livewire/Alpine compatibility
- No nonce generation or dynamic policy building
- No CSP violation reporting endpoint
- Config already references CSP violations in event logging (line 347)

### Limitations to Address
1. Static CSP cannot adapt to per-request requirements
2. `'unsafe-inline'` and `'unsafe-eval'` weaken security posture
3. No mechanism for nonce injection into Livewire/Alpine scripts
4. No violation reporting or monitoring capabilities
5. No debugging tools for CSP policy development

---

## Architecture Design

### Dependencies

- **artisanpack-ui/livewire-ui-components**: Used for dashboard UI components (cards, tables, badges, stats, charts)

### New Components

```
src/
├── Contracts/
│   └── CspPolicyInterface.php              # CSP service contract
├── Services/
│   └── Csp/
│       ├── CspPolicyBuilder.php            # Fluent policy builder
│       ├── CspNonceGenerator.php           # Cryptographic nonce generation
│       ├── CspPolicyService.php            # Main CSP service
│       ├── CspViolationHandler.php         # Violation processing
│       └── Presets/
│           ├── LivewirePreset.php          # Livewire-optimized preset
│           ├── StrictPreset.php            # Maximum security preset
│           └── RelaxedPreset.php           # Development-friendly preset
├── Http/
│   ├── Middleware/
│   │   └── ContentSecurityPolicy.php       # CSP middleware
│   └── Controllers/
│       └── CspViolationController.php      # Violation reporting endpoint
├── Events/
│   ├── CspViolationReceived.php            # Violation event
│   └── CspPolicyApplied.php                # Policy application event
├── Models/
│   └── CspViolationReport.php              # Violation storage model
├── Livewire/
│   └── CspDashboard.php                    # CSP monitoring dashboard
├── View/
│   └── Components/
│       └── CspNonce.php                    # Blade component for nonces
├── Console/Commands/
│   ├── CspAnalyzeCommand.php               # Analyze CSP violations
│   └── CspTestCommand.php                  # Test CSP configuration
├── Testing/
│   └── CspAssertions.php                   # Testing utilities trait
└── Facades/
    └── Csp.php                             # CSP facade
```

### Database Migrations

```
database/migrations/
└── create_csp_violation_reports_table.php  # Violation storage
```

---

## Implementation Phases

### Phase 1: Core CSP Infrastructure

#### 1.1 CSP Policy Interface

**File:** `src/Contracts/CspPolicyInterface.php`

```php
interface CspPolicyInterface
{
    public function getNonce(): string;
    public function addDirective(string $directive, string|array $values): self;
    public function getPolicy(): string;
    public function getReportOnlyPolicy(): string;
    public function toHeader(): array;
}
```

**Key Methods:**
- `getNonce()` - Returns the current request's nonce
- `addDirective()` - Adds values to a CSP directive
- `getPolicy()` - Builds the final CSP header string
- `getReportOnlyPolicy()` - Builds report-only variant
- `toHeader()` - Returns array suitable for response headers

#### 1.2 Nonce Generator Service

**File:** `src/Services/Csp/CspNonceGenerator.php`

**Responsibilities:**
- Generate cryptographically secure nonces per request
- Store nonce in request attributes for reuse
- Provide base64-encoded nonce string
- Integrate with Laravel's request lifecycle

**Implementation Details:**
```php
class CspNonceGenerator
{
    protected ?string $nonce = null;

    public function generate(): string
    {
        if ($this->nonce === null) {
            $this->nonce = base64_encode(random_bytes(16));
        }
        return $this->nonce;
    }

    public function get(): string
    {
        return $this->nonce ?? $this->generate();
    }

    public function reset(): void
    {
        $this->nonce = null;
    }
}
```

**Service Registration:**
- Register as scoped singleton (per-request lifecycle)
- Bind to container for dependency injection

#### 1.3 CSP Policy Builder

**File:** `src/Services/Csp/CspPolicyBuilder.php`

**Fluent API Design:**
```php
$policy = CspPolicyBuilder::create()
    ->defaultSrc("'self'")
    ->scriptSrc("'self'", "'nonce-{$nonce}'")
    ->styleSrc("'self'", "'nonce-{$nonce}'")
    ->imgSrc("'self'", 'data:', 'https:')
    ->connectSrc("'self'")
    ->fontSrc("'self'", 'https://fonts.bunny.net')
    ->frameAncestors("'self'")
    ->baseUri("'self'")
    ->formAction("'self'")
    ->reportUri('/csp-violation')
    ->build();
```

**Supported Directives:**
| Directive | Description |
|-----------|-------------|
| `default-src` | Fallback for other directives |
| `script-src` | JavaScript sources |
| `script-src-elem` | Script element sources |
| `script-src-attr` | Inline script attribute sources |
| `style-src` | Stylesheet sources |
| `style-src-elem` | Style element sources |
| `style-src-attr` | Inline style attribute sources |
| `img-src` | Image sources |
| `font-src` | Font sources |
| `connect-src` | XHR/WebSocket/EventSource |
| `media-src` | Audio/video sources |
| `object-src` | Plugin sources |
| `frame-src` | Frame sources |
| `frame-ancestors` | Embedding restrictions |
| `base-uri` | Base URL restrictions |
| `form-action` | Form submission targets |
| `report-uri` | Violation report endpoint |
| `report-to` | Reporting API endpoint |
| `upgrade-insecure-requests` | HTTPS upgrade |
| `block-all-mixed-content` | Block HTTP on HTTPS |

**Features:**
- Immutable builder pattern
- Automatic nonce injection
- Directive validation
- Hash generation for inline scripts/styles
- Preset merging capabilities

#### 1.4 CSP Policy Service

**File:** `src/Services/Csp/CspPolicyService.php`

**Responsibilities:**
- Coordinate nonce generation and policy building
- Apply presets based on configuration
- Handle route-specific policies
- Manage report-only mode
- Integrate with SecurityEventLogger for violations

**Configuration-Driven Behavior:**
```php
class CspPolicyService implements CspPolicyInterface
{
    public function __construct(
        protected CspNonceGenerator $nonceGenerator,
        protected CspPolicyBuilder $builder,
        protected ?SecurityEventLoggerInterface $logger = null,
    ) {}

    public function forRequest(Request $request): self
    {
        // Apply route-specific or default policy
        $preset = $this->determinePreset($request);
        $this->applyPreset($preset);

        return $this;
    }
}
```

---

### Phase 2: Livewire Integration

#### 2.1 Livewire-Compatible CSP Rules

**File:** `src/Services/Csp/Presets/LivewirePreset.php`

**Livewire/Alpine.js Requirements:**
- Nonces for inline scripts (Livewire component scripts)
- `'self'` for script-src (Livewire.js)
- WebSocket/EventSource for `connect-src` (if using Echo)
- Specific handling for `x-data`, `x-on`, `@click` attributes

**Preset Configuration:**
```php
class LivewirePreset
{
    public function apply(CspPolicyBuilder $builder, string $nonce): CspPolicyBuilder
    {
        return $builder
            ->defaultSrc("'self'")
            ->scriptSrc("'self'", "'nonce-{$nonce}'", "'strict-dynamic'")
            ->scriptSrcElem("'self'", "'nonce-{$nonce}'")
            ->styleSrc("'self'", "'nonce-{$nonce}'")
            ->styleSrcElem("'self'", "'nonce-{$nonce}'")
            ->imgSrc("'self'", 'data:', 'blob:')
            ->connectSrc("'self'", 'wss:', 'ws:')
            ->fontSrc("'self'", 'data:')
            ->objectSrc("'none'")
            ->baseUri("'self'")
            ->formAction("'self'")
            ->frameAncestors("'self'");
    }
}
```

**Note on `strict-dynamic`:**
- Allows scripts loaded by nonced scripts to execute
- Essential for Livewire's dynamic script loading
- Automatically ignores `'unsafe-inline'` when present

#### 2.2 Nonce Injection for Blade/Livewire

**Blade Directive Registration:**
```php
// In SecurityServiceProvider
Blade::directive('cspNonce', function () {
    return '<?php echo app(\ArtisanPackUI\Security\Contracts\CspPolicyInterface::class)->getNonce(); ?>';
});

Blade::directive('cspMeta', function () {
    return '<?php echo app(\ArtisanPackUI\Security\Services\Csp\CspPolicyService::class)->renderMetaTag(); ?>';
});
```

**Usage in Blade Templates:**
```html
<!-- Inline script with nonce -->
<script nonce="@cspNonce">
    // Your inline JavaScript
</script>

<!-- Meta tag for JavaScript access -->
@cspMeta
```

#### 2.3 Blade Component for Nonces

**File:** `src/View/Components/CspNonce.php`

```php
class CspNonce extends Component
{
    public string $nonce;

    public function __construct(CspPolicyInterface $csp)
    {
        $this->nonce = $csp->getNonce();
    }

    public function render()
    {
        return <<<'blade'
            {{ $nonce }}
        blade;
    }
}
```

**Usage:**
```html
<script nonce="<x-csp-nonce />">
    // Inline script
</script>
```

#### 2.4 Livewire Script Stack Integration

**Approach:** Hook into Livewire's script rendering to inject nonces automatically.

**File:** `src/Listeners/InjectCspNonceIntoLivewire.php`

**Strategy:**
1. Listen for Livewire's response rendering
2. Inject nonce attribute into generated script tags
3. Handle both Livewire v2 and v3 patterns

**For Livewire 3:**
```php
// In service provider boot method
Livewire::listen('render', function ($component, $view) {
    // Inject nonce into component scripts
});
```

**Alternative: Middleware Response Processing:**
- Parse response HTML after Livewire rendering
- Add nonce to Livewire-generated script tags
- More reliable but slightly higher overhead

---

### Phase 3: Violation Reporting

#### 3.1 Violation Reporting Endpoint

**File:** `src/Http/Controllers/CspViolationController.php`

```php
class CspViolationController extends Controller
{
    public function __construct(
        protected CspViolationHandler $handler,
    ) {}

    public function report(Request $request): Response
    {
        // Validate CSP report format
        $report = $request->json()->all();

        // Process and store violation
        $this->handler->handle($report);

        return response()->noContent();
    }
}
```

**Route Registration:**
```php
Route::post('/csp-violation', [CspViolationController::class, 'report'])
    ->name('csp.violation.report')
    ->middleware(['throttle:csp-reports']);
```

**Security Considerations:**
- Rate limiting to prevent DoS via report flooding
- Validate report structure matches CSP spec
- No authentication required (reports come from browser)
- CORS headers for cross-origin reports

#### 3.2 Violation Report Model

**File:** `src/Models/CspViolationReport.php`

**Schema:**
```php
Schema::create('csp_violation_reports', function (Blueprint $table) {
    $table->id();
    $table->string('document_uri', 2048);
    $table->string('blocked_uri', 2048)->nullable();
    $table->string('violated_directive');
    $table->string('effective_directive')->nullable();
    $table->text('original_policy')->nullable();
    $table->string('disposition')->default('enforce'); // enforce|report
    $table->string('referrer', 2048)->nullable();
    $table->text('script_sample')->nullable();
    $table->string('source_file', 2048)->nullable();
    $table->unsignedInteger('line_number')->nullable();
    $table->unsignedInteger('column_number')->nullable();
    $table->string('status_code')->nullable();
    $table->string('user_agent')->nullable();
    $table->string('ip_address', 45)->nullable();
    $table->string('fingerprint')->index(); // For deduplication
    $table->unsignedInteger('occurrence_count')->default(1);
    $table->timestamp('first_seen_at');
    $table->timestamp('last_seen_at');
    $table->timestamps();

    $table->index(['violated_directive', 'created_at']);
    $table->index(['blocked_uri', 'created_at']);
});
```

**Model Features:**
```php
class CspViolationReport extends Model
{
    // Scopes
    public function scopeRecent(Builder $query, int $hours = 24): Builder;
    public function scopeByDirective(Builder $query, string $directive): Builder;
    public function scopeGroupedByUri(Builder $query): Builder;

    // Deduplication via fingerprint
    public static function recordViolation(array $report): self;

    // Analytics
    public static function getTopViolations(int $limit = 10): Collection;
    public static function getViolationTrend(int $days = 7): array;
}
```

#### 3.3 Violation Handler Service

**File:** `src/Services/Csp/CspViolationHandler.php`

**Responsibilities:**
- Parse CSP violation reports
- Validate report structure
- Generate fingerprint for deduplication
- Store or update violation records
- Dispatch events for real-time notifications
- Integrate with SecurityEventLogger

```php
class CspViolationHandler
{
    public function handle(array $report): CspViolationReport
    {
        // Extract csp-report from wrapper
        $cspReport = $report['csp-report'] ?? $report;

        // Validate required fields
        $this->validateReport($cspReport);

        // Generate fingerprint
        $fingerprint = $this->generateFingerprint($cspReport);

        // Upsert violation
        $violation = CspViolationReport::updateOrCreate(
            ['fingerprint' => $fingerprint],
            [
                // Map report fields
                'last_seen_at' => now(),
            ]
        );

        // Increment counter if existing
        if (!$violation->wasRecentlyCreated) {
            $violation->increment('occurrence_count');
        }

        // Dispatch event
        event(new CspViolationReceived($violation));

        // Log to security events
        $this->logSecurityEvent($violation);

        return $violation;
    }
}
```

#### 3.4 CSP Violation Event

**File:** `src/Events/CspViolationReceived.php`

```php
class CspViolationReceived
{
    use Dispatchable, InteractsWithSockets, SerializesModels;

    public function __construct(
        public readonly CspViolationReport $violation,
    ) {}
}
```

**Use Cases:**
- Real-time dashboard updates via Livewire
- Slack/email notifications for critical violations
- Integration with monitoring systems

---

### Phase 4: CSP Middleware

#### 4.1 Content Security Policy Middleware

**File:** `src/Http/Middleware/ContentSecurityPolicy.php`

```php
class ContentSecurityPolicy
{
    public function __construct(
        protected CspPolicyService $csp,
    ) {}

    public function handle(Request $request, Closure $next, ?string $preset = null): Response
    {
        // Skip if CSP is disabled
        if (!config('artisanpack.security.csp.enabled', true)) {
            return $next($request);
        }

        // Build policy for this request
        $this->csp->forRequest($request);

        // Apply preset if specified
        if ($preset) {
            $this->csp->usePreset($preset);
        }

        // Get response
        $response = $next($request);

        // Apply CSP headers
        return $this->applyHeaders($response);
    }

    protected function applyHeaders(Response $response): Response
    {
        $headers = $this->csp->toHeader();

        foreach ($headers as $name => $value) {
            $response->headers->set($name, $value);
        }

        // Dispatch policy applied event
        event(new CspPolicyApplied($this->csp->getPolicy()));

        return $response;
    }
}
```

**Middleware Parameters:**
```php
// In routes
Route::middleware('csp:livewire')->group(function () {
    // Livewire routes
});

Route::middleware('csp:strict')->group(function () {
    // High-security routes
});

Route::middleware('csp:relaxed')->group(function () {
    // Development/testing routes
});
```

#### 4.2 Report-Only Mode Support

**Configuration:**
```php
'csp' => [
    'enabled' => env('CSP_ENABLED', true),
    'reportOnly' => env('CSP_REPORT_ONLY', false),
    // When true, uses Content-Security-Policy-Report-Only header
]
```

**Middleware Logic:**
```php
protected function applyHeaders(Response $response): Response
{
    $policy = $this->csp->getPolicy();

    if (config('artisanpack.security.csp.reportOnly', false)) {
        $response->headers->set('Content-Security-Policy-Report-Only', $policy);
    } else {
        $response->headers->set('Content-Security-Policy', $policy);

        // Optionally also send report-only for monitoring
        if (config('artisanpack.security.csp.dualHeader', false)) {
            $response->headers->set('Content-Security-Policy-Report-Only', $policy);
        }
    }

    return $response;
}
```

---

### Phase 5: Configuration Management

#### 5.1 CSP Configuration Section

**File:** `config/artisanpack/security.php` (new section)

```php
'csp' => [
    /*
    |--------------------------------------------------------------------------
    | Enable Content Security Policy
    |--------------------------------------------------------------------------
    |
    | Master switch for the CSP framework. When disabled, no CSP headers
    | will be added to responses.
    |
    */
    'enabled' => env('CSP_ENABLED', true),

    /*
    |--------------------------------------------------------------------------
    | Report-Only Mode
    |--------------------------------------------------------------------------
    |
    | When enabled, uses Content-Security-Policy-Report-Only header instead
    | of enforcing the policy. Useful for testing policies before deployment.
    |
    */
    'reportOnly' => env('CSP_REPORT_ONLY', false),

    /*
    |--------------------------------------------------------------------------
    | Default Preset
    |--------------------------------------------------------------------------
    |
    | The default CSP preset to use. Available presets:
    | - livewire: Optimized for Livewire/Alpine.js applications
    | - strict: Maximum security (may break some functionality)
    | - relaxed: Development-friendly (less secure)
    | - custom: Use custom directives defined below
    |
    */
    'preset' => env('CSP_PRESET', 'livewire'),

    /*
    |--------------------------------------------------------------------------
    | Nonce Generation
    |--------------------------------------------------------------------------
    */
    'nonce' => [
        // Whether to generate nonces for inline scripts/styles
        'enabled' => true,

        // Byte length for nonce (16 = 128-bit)
        'length' => 16,

        // Add meta tag with nonce for JavaScript access
        'metaTag' => true,
    ],

    /*
    |--------------------------------------------------------------------------
    | Violation Reporting
    |--------------------------------------------------------------------------
    */
    'reporting' => [
        // Enable violation reporting endpoint
        'enabled' => env('CSP_REPORTING_ENABLED', true),

        // Report endpoint URI (relative to app URL)
        'uri' => '/csp-violation',

        // Store violations in database
        'storeViolations' => true,

        // Log violations to security event log
        'logToSecurityEvents' => true,

        // Rate limit for violation reports (per minute per IP)
        'rateLimit' => 60,

        // Retention period for violation reports (days)
        'retentionDays' => 30,
    ],

    /*
    |--------------------------------------------------------------------------
    | Directive Defaults
    |--------------------------------------------------------------------------
    |
    | Base directives that apply to all presets. Presets can override these.
    |
    */
    'directives' => [
        'default-src' => ["'self'"],
        'script-src' => ["'self'"],
        'style-src' => ["'self'"],
        'img-src' => ["'self'", 'data:'],
        'font-src' => ["'self'"],
        'connect-src' => ["'self'"],
        'media-src' => ["'self'"],
        'object-src' => ["'none'"],
        'frame-src' => ["'self'"],
        'frame-ancestors' => ["'self'"],
        'base-uri' => ["'self'"],
        'form-action' => ["'self'"],
        'upgrade-insecure-requests' => true,
    ],

    /*
    |--------------------------------------------------------------------------
    | Additional Sources
    |--------------------------------------------------------------------------
    |
    | Add trusted sources to specific directives. These are merged with
    | preset and default directives.
    |
    */
    'additionalSources' => [
        'script-src' => [
            // 'https://cdn.example.com',
        ],
        'style-src' => [
            'https://fonts.bunny.net',
            'https://fonts.googleapis.com',
        ],
        'font-src' => [
            'https://fonts.bunny.net',
            'https://fonts.gstatic.com',
        ],
        'img-src' => [
            // 'https://images.example.com',
        ],
        'connect-src' => [
            // 'wss://socket.example.com',
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Route-Specific Policies
    |--------------------------------------------------------------------------
    |
    | Define different CSP policies for specific routes or route patterns.
    |
    */
    'routePolicies' => [
        // 'admin/*' => 'strict',
        // 'api/*' => 'api',
        // 'public/*' => 'relaxed',
    ],

    /*
    |--------------------------------------------------------------------------
    | Excluded Routes
    |--------------------------------------------------------------------------
    |
    | Routes that should not have CSP headers applied.
    |
    */
    'excludedRoutes' => [
        // 'webhook/*',
        // 'csp-violation',
    ],

    /*
    |--------------------------------------------------------------------------
    | Debugging
    |--------------------------------------------------------------------------
    */
    'debug' => [
        // Log CSP policy to Laravel log
        'logPolicy' => env('CSP_DEBUG', false),

        // Add CSP-Policy-Nonce meta tag for debugging
        'exposeNonce' => env('APP_DEBUG', false),
    ],
],
```

#### 5.2 Preset Configuration

**Individual Preset Files:**

**File:** `config/artisanpack/csp-presets/livewire.php`
```php
return [
    'default-src' => ["'self'"],
    'script-src' => ["'self'", "'strict-dynamic'", "'nonce-{nonce}'"],
    'script-src-elem' => ["'self'", "'nonce-{nonce}'"],
    'style-src' => ["'self'", "'nonce-{nonce}'"],
    'style-src-elem' => ["'self'", "'nonce-{nonce}'"],
    'img-src' => ["'self'", 'data:', 'blob:'],
    'font-src' => ["'self'", 'data:'],
    'connect-src' => ["'self'", 'wss:', 'ws:'],
    'object-src' => ["'none'"],
    'base-uri' => ["'self'"],
    'form-action' => ["'self'"],
    'frame-ancestors' => ["'self'"],
    'upgrade-insecure-requests' => true,
];
```

**File:** `config/artisanpack/csp-presets/strict.php`
```php
return [
    'default-src' => ["'none'"],
    'script-src' => ["'self'", "'nonce-{nonce}'"],
    'style-src' => ["'self'", "'nonce-{nonce}'"],
    'img-src' => ["'self'"],
    'font-src' => ["'self'"],
    'connect-src' => ["'self'"],
    'object-src' => ["'none'"],
    'base-uri' => ["'none'"],
    'form-action' => ["'self'"],
    'frame-ancestors' => ["'none'"],
    'upgrade-insecure-requests' => true,
    'block-all-mixed-content' => true,
];
```

---

### Phase 6: Debugging & Testing Tools

#### 6.1 CSP Analyze Command

**File:** `src/Console/Commands/CspAnalyzeCommand.php`

```bash
php artisan security:csp-analyze
```

**Features:**
- Show current CSP configuration
- List recent violations grouped by directive
- Identify potential policy issues
- Suggest policy improvements
- Export violation report

**Output Example:**
```
CSP Analysis Report
==================

Current Policy:
  Preset: livewire
  Mode: enforce

Violation Summary (last 24h):
  script-src: 15 violations
  style-src: 3 violations
  img-src: 0 violations

Top Blocked URIs:
  1. https://analytics.example.com (12 occurrences)
  2. inline script (3 occurrences)

Recommendations:
  - Add 'https://analytics.example.com' to script-src if trusted
  - Review inline scripts for nonce compliance
```

#### 6.2 CSP Test Command

**File:** `src/Console/Commands/CspTestCommand.php`

```bash
php artisan security:csp-test [url] [--preset=livewire]
```

**Features:**
- Make HTTP request to specified URL
- Display CSP header in parsed format
- Validate header syntax
- Check nonce generation
- Compare against expected policy

**Output Example:**
```
Testing CSP for: https://example.com/dashboard

CSP Header Present: Yes
Header Type: Content-Security-Policy (enforcing)

Parsed Directives:
  default-src: 'self'
  script-src: 'self' 'nonce-abc123...' 'strict-dynamic'
  style-src: 'self' 'nonce-abc123...'
  ...

Nonce Detected: Yes (abc123...)
Nonce in Meta Tag: Yes

Validation:
  ✓ No 'unsafe-inline' in script-src
  ✓ No 'unsafe-eval' in script-src
  ✓ report-uri configured
  ✓ frame-ancestors set

Result: PASS
```

#### 6.3 CSP Dashboard Component

**File:** `src/Livewire/CspDashboard.php`

**Features:**
- Real-time violation monitoring
- Violation trend charts
- Top blocked URIs
- Directive violation breakdown
- Policy configuration viewer
- Quick policy adjustment controls

**View Integration:**
The dashboard view should leverage the `artisanpack-ui/livewire-ui-components` package for consistent UI components:
- Use `<x-artisanpack-card>` for violation summary panels
- Use `<x-artisanpack-table>` for violation listings with sorting and pagination
- Use `<x-artisanpack-badge>` for directive labels and status indicators
- Use `<x-artisanpack-stat>` for violation count displays with icons
- Use `<x-artisanpack-alert>` for policy warnings and recommendations
- Use `<x-artisanpack-chart>` for trend visualization

**View:** `resources/views/livewire/csp-dashboard.blade.php`

#### 6.4 Testing Utilities Trait

**File:** `src/Testing/CspAssertions.php`

```php
trait CspAssertions
{
    public function assertCspHeaderPresent(TestResponse $response): self
    {
        $response->assertHeader('Content-Security-Policy');
        return $this;
    }

    public function assertCspContainsNonce(TestResponse $response): self
    {
        $csp = $response->headers->get('Content-Security-Policy');
        $this->assertMatchesRegularExpression(
            "/'nonce-[A-Za-z0-9+\/=]+'/",
            $csp
        );
        return $this;
    }

    public function assertCspDirective(
        TestResponse $response,
        string $directive,
        array $expectedValues
    ): self;

    public function assertCspDoesNotContain(
        TestResponse $response,
        string $value
    ): self;

    public function assertNoUnsafeInline(TestResponse $response): self
    {
        $csp = $response->headers->get('Content-Security-Policy');
        $this->assertStringNotContainsString("'unsafe-inline'", $csp);
        return $this;
    }

    public function assertNoUnsafeEval(TestResponse $response): self
    {
        $csp = $response->headers->get('Content-Security-Policy');
        $this->assertStringNotContainsString("'unsafe-eval'", $csp);
        return $this;
    }
}
```

**Usage in Tests:**
```php
class MyFeatureTest extends TestCase
{
    use CspAssertions;

    public function test_page_has_secure_csp()
    {
        $response = $this->get('/dashboard');

        $this->assertCspHeaderPresent($response)
             ->assertCspContainsNonce($response)
             ->assertNoUnsafeInline($response)
             ->assertNoUnsafeEval($response);
    }
}
```

---

### Phase 7: Service Provider Integration

#### 7.1 Registration in SecurityServiceProvider

**Additions to `SecurityServiceProvider::register()`:**

```php
// CSP Services
$this->app->scoped(CspNonceGenerator::class);

$this->app->singleton(CspPolicyInterface::class, function ($app) {
    return new CspPolicyService(
        $app->make(CspNonceGenerator::class),
        new CspPolicyBuilder(),
        $app->make(SecurityEventLoggerInterface::class),
    );
});

$this->app->alias(CspPolicyInterface::class, 'csp');
```

#### 7.2 Boot Method Additions

```php
public function boot(): void
{
    // ... existing boot code ...

    // CSP Blade directives
    if (class_exists('Blade')) {
        Blade::directive('cspNonce', function () {
            return "<?php echo app('csp')->getNonce(); ?>";
        });

        Blade::directive('cspMeta', function () {
            return "<?php echo app('csp')->renderMetaTag(); ?>";
        });
    }

    // CSP routes
    $this->registerCspRoutes();

    // CSP commands
    if ($this->app->runningInConsole()) {
        $this->commands([
            CspAnalyzeCommand::class,
            CspTestCommand::class,
        ]);
    }
}

protected function registerCspRoutes(): void
{
    if (! config('artisanpack.security.csp.reporting.enabled', true)) {
        return;
    }

    Route::post(
        config('artisanpack.security.csp.reporting.uri', '/csp-violation'),
        [CspViolationController::class, 'report']
    )
        ->name('csp.violation.report')
        ->middleware(['throttle:csp-reports']);
}
```

#### 7.3 Middleware Alias Registration

```php
protected $middlewareAliases = [
    // ... existing aliases ...
    'csp' => ContentSecurityPolicy::class,
];
```

---

## Testing Strategy

### Unit Tests

| Test Class | Coverage |
|------------|----------|
| `CspNonceGeneratorTest` | Nonce generation, uniqueness, format |
| `CspPolicyBuilderTest` | Builder fluent API, directive validation |
| `CspPolicyServiceTest` | Policy assembly, preset application |
| `CspViolationHandlerTest` | Report parsing, deduplication, storage |
| `LivewirePresetTest` | Preset directive correctness |

### Feature Tests

| Test Class | Coverage |
|------------|----------|
| `CspMiddlewareTest` | Header application, route policies |
| `CspViolationEndpointTest` | Report receiving, rate limiting |
| `CspLivewireIntegrationTest` | Nonce injection, script execution |
| `CspDashboardTest` | Dashboard rendering, real-time updates |
| `CspCommandsTest` | CLI command functionality |

### Integration Tests

- Test actual Livewire component rendering with CSP
- Verify Alpine.js works with nonce-based CSP
- Confirm violation reporting in production-like environment

---

## File Summary

### New Files to Create

| File | Purpose |
|------|---------|
| `src/Contracts/CspPolicyInterface.php` | CSP service contract |
| `src/Services/Csp/CspNonceGenerator.php` | Nonce generation |
| `src/Services/Csp/CspPolicyBuilder.php` | Fluent policy builder |
| `src/Services/Csp/CspPolicyService.php` | Main CSP service |
| `src/Services/Csp/CspViolationHandler.php` | Violation processing |
| `src/Services/Csp/Presets/LivewirePreset.php` | Livewire preset |
| `src/Services/Csp/Presets/StrictPreset.php` | Strict preset |
| `src/Services/Csp/Presets/RelaxedPreset.php` | Relaxed preset |
| `src/Http/Middleware/ContentSecurityPolicy.php` | CSP middleware |
| `src/Http/Controllers/CspViolationController.php` | Violation endpoint |
| `src/Events/CspViolationReceived.php` | Violation event |
| `src/Events/CspPolicyApplied.php` | Policy applied event |
| `src/Models/CspViolationReport.php` | Violation model |
| `src/Livewire/CspDashboard.php` | Monitoring dashboard |
| `src/View/Components/CspNonce.php` | Blade component |
| `src/Console/Commands/CspAnalyzeCommand.php` | Analysis command |
| `src/Console/Commands/CspTestCommand.php` | Testing command |
| `src/Testing/CspAssertions.php` | Test utilities |
| `src/Facades/Csp.php` | CSP facade |
| `database/migrations/xxxx_create_csp_violation_reports_table.php` | Migration |
| `resources/views/livewire/csp-dashboard.blade.php` | Dashboard view (uses `artisanpack-ui/livewire-ui-components`) |
| `config/artisanpack/csp-presets/livewire.php` | Livewire preset config |
| `config/artisanpack/csp-presets/strict.php` | Strict preset config |
| `config/artisanpack/csp-presets/relaxed.php` | Relaxed preset config |

### Files to Modify

| File | Changes |
|------|---------|
| `config/artisanpack/security.php` | Add `csp` configuration section |
| `src/SecurityServiceProvider.php` | Register CSP services, middleware, routes |

---

## Documentation Requirements

### User Documentation

1. **Getting Started Guide**
   - Quick setup for Livewire applications
   - Configuration overview
   - Common customization scenarios

2. **Configuration Reference**
   - All configuration options explained
   - Environment variables
   - Preset descriptions

3. **Livewire Integration Guide**
   - Nonce usage in Blade templates
   - Alpine.js compatibility
   - Troubleshooting common issues

4. **Violation Monitoring Guide**
   - Dashboard usage
   - Interpreting violation reports
   - Policy adjustment workflow

5. **Testing Guide**
   - Using CspAssertions trait
   - Testing strategies
   - CI/CD integration

### API Documentation

- All public methods documented with PHPDoc
- Interface contracts fully documented
- Configuration options with examples

---

## Implementation Order

1. **Phase 1:** Core infrastructure (Nonce generator, Policy builder, Policy service)
2. **Phase 2:** Middleware and basic Livewire integration
3. **Phase 3:** Violation reporting (Endpoint, Model, Handler)
4. **Phase 4:** Configuration management
5. **Phase 5:** Presets (Livewire, Strict, Relaxed)
6. **Phase 6:** Console commands and debugging tools
7. **Phase 7:** Dashboard and testing utilities
8. **Phase 8:** Documentation and final testing

---

## Acceptance Criteria Checklist

- [ ] Create CSP policy generator service (`CspPolicyService`, `CspPolicyBuilder`)
- [ ] Implement Livewire-compatible CSP rules (`LivewirePreset`, nonce injection)
- [ ] Add nonce generation for inline scripts (`CspNonceGenerator`, Blade directives)
- [ ] Create CSP violation reporting endpoint (`CspViolationController`, model, handler)
- [ ] Implement CSP policy testing utilities (`CspAssertions` trait)
- [ ] Add CSP configuration management (config section, presets, route policies)
- [ ] Create CSP debugging tools (`CspAnalyzeCommand`, `CspTestCommand`, `CspDashboard`)
- [ ] Add comprehensive CSP documentation (user guides, API docs)
