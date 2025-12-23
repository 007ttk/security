# Security Testing Framework Implementation Plan

## Overview

This document outlines the implementation of a comprehensive security testing framework for the ArtisanPackUI Security package. The framework will provide automated vulnerability scanning, OWASP Top 10 testing, dependency scanning, penetration testing utilities, and CI/CD integration to help developers identify and remediate security issues early in the development lifecycle.

## Goals

1. Provide reusable security test base classes and traits
2. Automate OWASP Top 10 vulnerability testing
3. Integrate dependency vulnerability scanning
4. Create penetration testing utilities for common attack vectors
5. Enable security regression testing
6. Measure performance impact of security features
7. Generate comprehensive security test reports
8. Integrate seamlessly with CI/CD pipelines

## Architecture

```
src/
├── Testing/
│   ├── SecurityTestCase.php              # Base test class
│   ├── Traits/
│   │   ├── TestsAuthentication.php       # Auth testing helpers
│   │   ├── TestsAuthorization.php        # RBAC testing helpers
│   │   ├── TestsInputValidation.php      # Input validation tests
│   │   ├── TestsSessionSecurity.php      # Session security tests
│   │   ├── TestsCryptography.php         # Crypto testing helpers
│   │   └── TestsSecurityHeaders.php      # Header testing helpers
│   ├── Scanners/
│   │   ├── ScannerInterface.php          # Scanner contract
│   │   ├── OwaspScanner.php              # OWASP Top 10 scanner
│   │   ├── DependencyScanner.php         # Dependency vulnerability scanner
│   │   ├── HeaderScanner.php             # Security header scanner
│   │   └── ConfigurationScanner.php      # Security config scanner
│   ├── PenetrationTesting/
│   │   ├── AttackSimulator.php           # Base attack simulator
│   │   ├── Attacks/
│   │   │   ├── SqlInjectionAttack.php    # SQL injection tests
│   │   │   ├── XssAttack.php             # XSS attack tests
│   │   │   ├── CsrfAttack.php            # CSRF attack tests
│   │   │   ├── AuthBypassAttack.php      # Auth bypass tests
│   │   │   ├── InjectionAttack.php       # Generic injection tests
│   │   │   └── PathTraversalAttack.php   # Path traversal tests
│   │   └── Payloads/
│   │       ├── SqlPayloads.php           # SQL injection payloads
│   │       ├── XssPayloads.php           # XSS payloads
│   │       └── InjectionPayloads.php     # Generic injection payloads
│   ├── Performance/
│   │   ├── SecurityBenchmark.php         # Performance benchmarking
│   │   └── ImpactAnalyzer.php            # Impact analysis
│   ├── Reporting/
│   │   ├── SecurityReportGenerator.php   # Report generation
│   │   ├── Formats/
│   │   │   ├── HtmlReportFormat.php      # HTML reports
│   │   │   ├── JsonReportFormat.php      # JSON reports
│   │   │   ├── JunitReportFormat.php     # JUnit XML reports
│   │   │   └── SarifReportFormat.php     # SARIF reports for GitHub
│   │   └── SecurityFinding.php           # Finding model
│   └── CiCd/
│       ├── SecurityPipelineCommand.php   # CI/CD command
│       ├── GitHubActionsIntegration.php  # GitHub Actions support
│       └── SecurityGate.php              # Quality gate checks
├── Console/Commands/
│   ├── SecurityScan.php                  # Run security scans
│   ├── SecurityAudit.php                 # Full security audit
│   └── SecurityBenchmark.php             # Run benchmarks
└── Contracts/
    ├── SecurityScannerInterface.php      # Scanner contract
    └── SecurityReportInterface.php       # Report contract
```

## Implementation Phases

### Phase 1: Core Testing Infrastructure

#### 1.1 Security Test Base Class

```php
<?php

namespace ArtisanPackUI\Security\Testing;

use Illuminate\Foundation\Testing\TestCase;
use ArtisanPackUI\Security\Testing\Traits\TestsAuthentication;
use ArtisanPackUI\Security\Testing\Traits\TestsAuthorization;
use ArtisanPackUI\Security\Testing\Traits\TestsInputValidation;

abstract class SecurityTestCase extends TestCase
{
    use TestsAuthentication;
    use TestsAuthorization;
    use TestsInputValidation;

    protected array $securityFindings = [];
    protected bool $failOnVulnerability = true;
    protected string $severityThreshold = 'medium';

    protected function setUp(): void
    {
        parent::setUp();
        $this->securityFindings = [];
    }

    protected function tearDown(): void
    {
        $this->assertNoSecurityVulnerabilities();
        parent::tearDown();
    }

    protected function recordFinding(SecurityFinding $finding): void
    {
        $this->securityFindings[] = $finding;
    }

    protected function assertNoSecurityVulnerabilities(): void
    {
        if (!$this->failOnVulnerability) {
            return;
        }

        $critical = $this->getFindings('critical');
        $high = $this->getFindings('high');

        $this->assertEmpty(
            $critical,
            'Critical security vulnerabilities found: ' . $this->formatFindings($critical)
        );

        if ($this->severityThreshold === 'high' || $this->severityThreshold === 'medium') {
            $this->assertEmpty(
                $high,
                'High severity vulnerabilities found: ' . $this->formatFindings($high)
            );
        }
    }

    public function getFindings(?string $severity = null): array
    {
        if ($severity === null) {
            return $this->securityFindings;
        }

        return array_filter(
            $this->securityFindings,
            fn ($f) => $f->severity === $severity
        );
    }
}
```

#### 1.2 Security Finding Model

```php
<?php

namespace ArtisanPackUI\Security\Testing\Reporting;

class SecurityFinding
{
    public function __construct(
        public readonly string $id,
        public readonly string $title,
        public readonly string $description,
        public readonly string $severity, // critical, high, medium, low, info
        public readonly string $category,  // OWASP category or custom
        public readonly ?string $location = null,
        public readonly ?string $evidence = null,
        public readonly ?string $remediation = null,
        public readonly array $metadata = [],
    ) {}

    public static function critical(string $title, string $description, string $category): self
    {
        return new self(
            id: uniqid('SEC-'),
            title: $title,
            description: $description,
            severity: 'critical',
            category: $category
        );
    }

    public static function high(string $title, string $description, string $category): self
    {
        return new self(
            id: uniqid('SEC-'),
            title: $title,
            description: $description,
            severity: 'high',
            category: $category
        );
    }

    // Additional factory methods...

    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'title' => $this->title,
            'description' => $this->description,
            'severity' => $this->severity,
            'category' => $this->category,
            'location' => $this->location,
            'evidence' => $this->evidence,
            'remediation' => $this->remediation,
            'metadata' => $this->metadata,
        ];
    }
}
```

### Phase 2: OWASP Top 10 Testing

#### 2.1 OWASP Scanner

```php
<?php

namespace ArtisanPackUI\Security\Testing\Scanners;

class OwaspScanner implements ScannerInterface
{
    protected array $findings = [];

    /**
     * OWASP Top 10 2021 Categories:
     * A01: Broken Access Control
     * A02: Cryptographic Failures
     * A03: Injection
     * A04: Insecure Design
     * A05: Security Misconfiguration
     * A06: Vulnerable and Outdated Components
     * A07: Identification and Authentication Failures
     * A08: Software and Data Integrity Failures
     * A09: Security Logging and Monitoring Failures
     * A10: Server-Side Request Forgery (SSRF)
     */

    public function scan(): array
    {
        $this->findings = [];

        $this->scanBrokenAccessControl();      // A01
        $this->scanCryptographicFailures();    // A02
        $this->scanInjection();                // A03
        $this->scanInsecureDesign();           // A04
        $this->scanSecurityMisconfiguration(); // A05
        $this->scanVulnerableComponents();     // A06
        $this->scanAuthenticationFailures();   // A07
        $this->scanIntegrityFailures();        // A08
        $this->scanLoggingFailures();          // A09
        $this->scanSsrf();                     // A10

        return $this->findings;
    }

    protected function scanBrokenAccessControl(): void
    {
        // Check for missing authorization middleware
        // Check for IDOR vulnerabilities
        // Check for privilege escalation paths
        // Check for CORS misconfigurations
    }

    protected function scanCryptographicFailures(): void
    {
        // Check for weak algorithms
        // Check for hardcoded secrets
        // Check for insecure key storage
        // Check for missing encryption
    }

    protected function scanInjection(): void
    {
        // Check for SQL injection vulnerabilities
        // Check for command injection
        // Check for LDAP injection
        // Check for XSS vulnerabilities
    }

    // ... additional scan methods
}
```

#### 2.2 Testing Traits

```php
<?php

namespace ArtisanPackUI\Security\Testing\Traits;

trait TestsInputValidation
{
    /**
     * Test endpoint for SQL injection vulnerabilities.
     */
    protected function assertNotVulnerableToSqlInjection(
        string $method,
        string $uri,
        array $parameters,
        string $vulnerableParam
    ): void {
        $payloads = SqlPayloads::getAll();

        foreach ($payloads as $payload) {
            $testParams = $parameters;
            $testParams[$vulnerableParam] = $payload;

            $response = $this->$method($uri, $testParams);

            // Check for SQL error messages in response
            $this->assertNoSqlErrors($response, $payload);

            // Check for timing-based detection
            $this->assertNoTimingAnomaly($method, $uri, $testParams);
        }
    }

    /**
     * Test endpoint for XSS vulnerabilities.
     */
    protected function assertNotVulnerableToXss(
        string $method,
        string $uri,
        array $parameters,
        string $vulnerableParam
    ): void {
        $payloads = XssPayloads::getAll();

        foreach ($payloads as $payload) {
            $testParams = $parameters;
            $testParams[$vulnerableParam] = $payload;

            $response = $this->$method($uri, $testParams);

            // Check if payload is reflected unescaped
            $this->assertPayloadEscaped($response, $payload);
        }
    }

    /**
     * Test endpoint for command injection.
     */
    protected function assertNotVulnerableToCommandInjection(
        string $method,
        string $uri,
        array $parameters,
        string $vulnerableParam
    ): void {
        $payloads = InjectionPayloads::getCommandInjection();

        foreach ($payloads as $payload) {
            $testParams = $parameters;
            $testParams[$vulnerableParam] = $payload;

            $response = $this->$method($uri, $testParams);

            // Check for command execution indicators
            $this->assertNoCommandExecution($response, $payload);
        }
    }

    /**
     * Test for path traversal vulnerabilities.
     */
    protected function assertNotVulnerableToPathTraversal(
        string $method,
        string $uri,
        array $parameters,
        string $vulnerableParam
    ): void {
        $payloads = [
            '../../../etc/passwd',
            '....//....//....//etc/passwd',
            '..%2f..%2f..%2fetc/passwd',
            '..%252f..%252f..%252fetc/passwd',
            '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd',
        ];

        foreach ($payloads as $payload) {
            $testParams = $parameters;
            $testParams[$vulnerableParam] = $payload;

            $response = $this->$method($uri, $testParams);

            $this->assertNoSensitiveFileContent($response);
        }
    }
}
```

### Phase 3: Dependency Vulnerability Scanning

#### 3.1 Dependency Scanner

```php
<?php

namespace ArtisanPackUI\Security\Testing\Scanners;

class DependencyScanner implements ScannerInterface
{
    protected array $findings = [];
    protected ?string $advisoryDatabase = null;

    public function __construct(
        protected string $composerLockPath = 'composer.lock',
        protected string $packageLockPath = 'package-lock.json',
    ) {}

    public function scan(): array
    {
        $this->findings = [];

        $this->scanComposerDependencies();
        $this->scanNpmDependencies();

        return $this->findings;
    }

    protected function scanComposerDependencies(): void
    {
        if (!file_exists($this->composerLockPath)) {
            return;
        }

        $lock = json_decode(file_get_contents($this->composerLockPath), true);
        $packages = array_merge(
            $lock['packages'] ?? [],
            $lock['packages-dev'] ?? []
        );

        foreach ($packages as $package) {
            $vulnerabilities = $this->checkPackageVulnerabilities(
                $package['name'],
                $package['version'],
                'composer'
            );

            foreach ($vulnerabilities as $vuln) {
                $this->findings[] = SecurityFinding::fromVulnerability($vuln);
            }
        }
    }

    protected function scanNpmDependencies(): void
    {
        if (!file_exists($this->packageLockPath)) {
            return;
        }

        // Parse package-lock.json and check against npm audit
        $lock = json_decode(file_get_contents($this->packageLockPath), true);

        // Use npm audit --json or check against vulnerability database
        $this->runNpmAudit();
    }

    protected function checkPackageVulnerabilities(
        string $name,
        string $version,
        string $ecosystem
    ): array {
        // Check against:
        // - GitHub Advisory Database
        // - OSV (Open Source Vulnerabilities)
        // - Packagist Security Advisories
        // - FriendsOfPHP/security-advisories

        return [];
    }

    /**
     * Check against local security advisories database.
     */
    public function useLocalAdvisories(string $path): self
    {
        $this->advisoryDatabase = $path;
        return $this;
    }
}
```

### Phase 4: Penetration Testing Utilities

#### 4.1 Attack Simulator

```php
<?php

namespace ArtisanPackUI\Security\Testing\PenetrationTesting;

class AttackSimulator
{
    protected array $attacks = [];
    protected array $results = [];

    public function __construct(
        protected $testCase,
    ) {}

    public function registerAttack(AttackInterface $attack): self
    {
        $this->attacks[] = $attack;
        return $this;
    }

    public function simulate(string $uri, array $options = []): AttackResults
    {
        $this->results = [];

        foreach ($this->attacks as $attack) {
            $result = $attack->execute($this->testCase, $uri, $options);
            $this->results[] = $result;
        }

        return new AttackResults($this->results);
    }

    public static function fullScan($testCase): self
    {
        $simulator = new self($testCase);

        return $simulator
            ->registerAttack(new SqlInjectionAttack())
            ->registerAttack(new XssAttack())
            ->registerAttack(new CsrfAttack())
            ->registerAttack(new AuthBypassAttack())
            ->registerAttack(new PathTraversalAttack())
            ->registerAttack(new InjectionAttack());
    }
}
```

#### 4.2 Attack Implementations

```php
<?php

namespace ArtisanPackUI\Security\Testing\PenetrationTesting\Attacks;

class SqlInjectionAttack implements AttackInterface
{
    protected array $payloads;

    public function __construct()
    {
        $this->payloads = SqlPayloads::getAll();
    }

    public function execute($testCase, string $uri, array $options = []): AttackResult
    {
        $vulnerabilities = [];
        $method = $options['method'] ?? 'get';
        $params = $options['parameters'] ?? [];

        foreach ($params as $paramName => $originalValue) {
            foreach ($this->payloads as $payload) {
                $testParams = $params;
                $testParams[$paramName] = $payload;

                $startTime = microtime(true);
                $response = $testCase->$method($uri, $testParams);
                $duration = microtime(true) - $startTime;

                // Check for error-based SQLi
                if ($this->hasDbError($response)) {
                    $vulnerabilities[] = [
                        'type' => 'error-based',
                        'parameter' => $paramName,
                        'payload' => $payload,
                        'evidence' => $this->extractError($response),
                    ];
                }

                // Check for time-based SQLi
                if ($this->isTimeBased($payload) && $duration > 5) {
                    $vulnerabilities[] = [
                        'type' => 'time-based',
                        'parameter' => $paramName,
                        'payload' => $payload,
                        'duration' => $duration,
                    ];
                }

                // Check for boolean-based SQLi
                if ($this->detectBooleanBased($testCase, $uri, $method, $params, $paramName)) {
                    $vulnerabilities[] = [
                        'type' => 'boolean-based',
                        'parameter' => $paramName,
                    ];
                }
            }
        }

        return new AttackResult(
            attack: 'SQL Injection',
            vulnerable: !empty($vulnerabilities),
            findings: $vulnerabilities,
            severity: !empty($vulnerabilities) ? 'critical' : 'none'
        );
    }

    protected function hasDbError($response): bool
    {
        $errorPatterns = [
            '/sql syntax/i',
            '/mysql_fetch/i',
            '/ORA-\d+/i',
            '/PostgreSQL.*ERROR/i',
            '/SQLite3::query/i',
            '/SQLSTATE\[/i',
            '/Unclosed quotation mark/i',
            '/quoted string not properly terminated/i',
        ];

        $content = $response->getContent();

        foreach ($errorPatterns as $pattern) {
            if (preg_match($pattern, $content)) {
                return true;
            }
        }

        return false;
    }
}
```

#### 4.3 Payload Collections

```php
<?php

namespace ArtisanPackUI\Security\Testing\PenetrationTesting\Payloads;

class SqlPayloads
{
    public static function getAll(): array
    {
        return array_merge(
            self::getErrorBased(),
            self::getTimeBased(),
            self::getBooleanBased(),
            self::getUnionBased()
        );
    }

    public static function getErrorBased(): array
    {
        return [
            "'",
            "\"",
            "' OR '1'='1",
            "' OR '1'='1'--",
            "' OR '1'='1'/*",
            "1' ORDER BY 1--+",
            "1' ORDER BY 2--+",
            "1' UNION SELECT NULL--",
            "admin'--",
            "') OR ('1'='1",
        ];
    }

    public static function getTimeBased(): array
    {
        return [
            "' OR SLEEP(5)--",
            "'; WAITFOR DELAY '0:0:5'--",
            "' OR pg_sleep(5)--",
            "1' AND SLEEP(5)#",
            "1; SELECT SLEEP(5)",
        ];
    }

    public static function getBooleanBased(): array
    {
        return [
            "' AND '1'='1",
            "' AND '1'='2",
            "1 AND 1=1",
            "1 AND 1=2",
        ];
    }

    public static function getUnionBased(): array
    {
        return [
            "' UNION SELECT 1--",
            "' UNION SELECT 1,2--",
            "' UNION SELECT 1,2,3--",
            "' UNION ALL SELECT NULL,NULL--",
        ];
    }
}

class XssPayloads
{
    public static function getAll(): array
    {
        return array_merge(
            self::getBasic(),
            self::getEncoded(),
            self::getEventHandlers(),
            self::getPolyglots()
        );
    }

    public static function getBasic(): array
    {
        return [
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            '<body onload=alert(1)>',
            '<iframe src="javascript:alert(1)">',
        ];
    }

    public static function getEncoded(): array
    {
        return [
            '&lt;script&gt;alert(1)&lt;/script&gt;',
            '%3Cscript%3Ealert(1)%3C/script%3E',
            '&#60;script&#62;alert(1)&#60;/script&#62;',
            '\u003cscript\u003ealert(1)\u003c/script\u003e',
        ];
    }

    public static function getEventHandlers(): array
    {
        return [
            '" onmouseover="alert(1)',
            "' onfocus='alert(1)",
            '" autofocus onfocus="alert(1)',
            '<input type="text" onfocus="alert(1)" autofocus>',
        ];
    }

    public static function getPolyglots(): array
    {
        return [
            "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//",
            "'\"-->]]>*/</script></style></title></textarea></noscript></template></select>",
        ];
    }
}
```

### Phase 5: Security Regression Testing

#### 5.1 Regression Test Suite

```php
<?php

namespace ArtisanPackUI\Security\Testing;

trait SecurityRegressionTests
{
    /**
     * Define security regression tests that should always pass.
     */
    protected function getSecurityRegressions(): array
    {
        return [
            // Previously fixed vulnerabilities
            'CVE-2024-XXXX' => fn() => $this->testCve2024Xxxx(),

            // Custom security requirements
            'auth-bypass-fix' => fn() => $this->testAuthBypassFix(),
            'xss-in-comments' => fn() => $this->testXssInComments(),
        ];
    }

    /**
     * Run all security regression tests.
     */
    protected function runSecurityRegressionTests(): array
    {
        $results = [];

        foreach ($this->getSecurityRegressions() as $id => $test) {
            try {
                $test();
                $results[$id] = ['status' => 'passed'];
            } catch (\Throwable $e) {
                $results[$id] = [
                    'status' => 'failed',
                    'error' => $e->getMessage(),
                ];
            }
        }

        return $results;
    }

    /**
     * Assert that a previously fixed vulnerability remains fixed.
     */
    protected function assertVulnerabilityFixed(string $id, callable $test): void
    {
        try {
            $test();
        } catch (\Throwable $e) {
            $this->fail("Security regression: {$id} has regressed. {$e->getMessage()}");
        }
    }
}
```

### Phase 6: Performance Impact Testing

#### 6.1 Security Benchmark

```php
<?php

namespace ArtisanPackUI\Security\Testing\Performance;

class SecurityBenchmark
{
    protected array $results = [];

    /**
     * Benchmark a security feature's performance impact.
     */
    public function benchmark(string $name, callable $withSecurity, callable $withoutSecurity, int $iterations = 1000): BenchmarkResult
    {
        // Warmup
        for ($i = 0; $i < 10; $i++) {
            $withSecurity();
            $withoutSecurity();
        }

        // Benchmark with security
        $withSecurityTimes = [];
        for ($i = 0; $i < $iterations; $i++) {
            $start = hrtime(true);
            $withSecurity();
            $withSecurityTimes[] = hrtime(true) - $start;
        }

        // Benchmark without security
        $withoutSecurityTimes = [];
        for ($i = 0; $i < $iterations; $i++) {
            $start = hrtime(true);
            $withoutSecurity();
            $withoutSecurityTimes[] = hrtime(true) - $start;
        }

        $result = new BenchmarkResult(
            name: $name,
            withSecurity: $this->calculateStats($withSecurityTimes),
            withoutSecurity: $this->calculateStats($withoutSecurityTimes),
            iterations: $iterations
        );

        $this->results[] = $result;

        return $result;
    }

    /**
     * Benchmark middleware performance.
     */
    public function benchmarkMiddleware(string $middleware, $request = null): BenchmarkResult
    {
        $request ??= Request::create('/test', 'GET');
        $middlewareInstance = app($middleware);

        return $this->benchmark(
            name: "Middleware: {$middleware}",
            withSecurity: fn() => $middlewareInstance->handle($request, fn($r) => response('OK')),
            withoutSecurity: fn() => response('OK')
        );
    }

    /**
     * Benchmark validation rules.
     */
    public function benchmarkValidation(string $rule, mixed $value): BenchmarkResult
    {
        $validator = Validator::make(['field' => $value], ['field' => $rule]);

        return $this->benchmark(
            name: "Validation: {$rule}",
            withSecurity: fn() => $validator->passes(),
            withoutSecurity: fn() => true
        );
    }

    protected function calculateStats(array $times): array
    {
        sort($times);
        $count = count($times);

        return [
            'min' => min($times) / 1e6, // Convert to ms
            'max' => max($times) / 1e6,
            'mean' => array_sum($times) / $count / 1e6,
            'median' => $times[(int)($count / 2)] / 1e6,
            'p95' => $times[(int)($count * 0.95)] / 1e6,
            'p99' => $times[(int)($count * 0.99)] / 1e6,
        ];
    }

    public function generateReport(): array
    {
        return array_map(fn($r) => $r->toArray(), $this->results);
    }
}

class BenchmarkResult
{
    public function __construct(
        public readonly string $name,
        public readonly array $withSecurity,
        public readonly array $withoutSecurity,
        public readonly int $iterations,
    ) {}

    public function getOverhead(): float
    {
        return (($this->withSecurity['mean'] - $this->withoutSecurity['mean'])
            / $this->withoutSecurity['mean']) * 100;
    }

    public function isAcceptable(float $maxOverheadPercent = 10.0): bool
    {
        return $this->getOverhead() <= $maxOverheadPercent;
    }

    public function toArray(): array
    {
        return [
            'name' => $this->name,
            'iterations' => $this->iterations,
            'withSecurity' => $this->withSecurity,
            'withoutSecurity' => $this->withoutSecurity,
            'overhead' => [
                'percent' => $this->getOverhead(),
                'absolute_ms' => $this->withSecurity['mean'] - $this->withoutSecurity['mean'],
            ],
        ];
    }
}
```

### Phase 7: Security Reporting

#### 7.1 Report Generator

```php
<?php

namespace ArtisanPackUI\Security\Testing\Reporting;

class SecurityReportGenerator
{
    protected array $findings = [];
    protected array $metadata = [];

    public function __construct(
        protected string $projectName = '',
        protected ?string $version = null,
    ) {
        $this->metadata = [
            'generatedAt' => now()->toIso8601String(),
            'projectName' => $projectName,
            'version' => $version,
        ];
    }

    public function addFindings(array $findings): self
    {
        $this->findings = array_merge($this->findings, $findings);
        return $this;
    }

    public function addFinding(SecurityFinding $finding): self
    {
        $this->findings[] = $finding;
        return $this;
    }

    public function generate(string $format = 'json'): string
    {
        return match ($format) {
            'json' => $this->generateJson(),
            'html' => $this->generateHtml(),
            'junit' => $this->generateJunit(),
            'sarif' => $this->generateSarif(),
            'markdown' => $this->generateMarkdown(),
            default => throw new \InvalidArgumentException("Unknown format: {$format}"),
        };
    }

    protected function generateJson(): string
    {
        return json_encode([
            'metadata' => $this->metadata,
            'summary' => $this->getSummary(),
            'findings' => array_map(fn($f) => $f->toArray(), $this->findings),
        ], JSON_PRETTY_PRINT);
    }

    protected function generateSarif(): string
    {
        // SARIF format for GitHub Security tab integration
        return json_encode([
            '$schema' => 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
            'version' => '2.1.0',
            'runs' => [
                [
                    'tool' => [
                        'driver' => [
                            'name' => 'ArtisanPack Security Scanner',
                            'version' => $this->metadata['version'] ?? '1.0.0',
                            'rules' => $this->getSarifRules(),
                        ],
                    ],
                    'results' => $this->getSarifResults(),
                ],
            ],
        ], JSON_PRETTY_PRINT);
    }

    protected function generateJunit(): string
    {
        $xml = new \SimpleXMLElement('<?xml version="1.0" encoding="UTF-8"?><testsuites/>');

        $testsuite = $xml->addChild('testsuite');
        $testsuite->addAttribute('name', 'Security Tests');
        $testsuite->addAttribute('tests', (string)count($this->findings));
        $testsuite->addAttribute('failures', (string)$this->countBySeverity(['critical', 'high']));

        foreach ($this->findings as $finding) {
            $testcase = $testsuite->addChild('testcase');
            $testcase->addAttribute('name', $finding->title);
            $testcase->addAttribute('classname', $finding->category);

            if (in_array($finding->severity, ['critical', 'high'])) {
                $failure = $testcase->addChild('failure', htmlspecialchars($finding->description));
                $failure->addAttribute('type', $finding->severity);
            }
        }

        return $xml->asXML();
    }

    protected function generateHtml(): string
    {
        // Generate HTML report with styling
        $template = <<<'HTML'
<!DOCTYPE html>
<html>
<head>
    <title>Security Report - {{ projectName }}</title>
    <style>
        body { font-family: system-ui, sans-serif; margin: 2rem; }
        .critical { color: #dc2626; }
        .high { color: #ea580c; }
        .medium { color: #ca8a04; }
        .low { color: #2563eb; }
        .info { color: #6b7280; }
        .finding { border: 1px solid #e5e7eb; padding: 1rem; margin: 1rem 0; border-radius: 0.5rem; }
        .summary { display: grid; grid-template-columns: repeat(5, 1fr); gap: 1rem; margin-bottom: 2rem; }
        .summary-card { padding: 1rem; border-radius: 0.5rem; text-align: center; }
    </style>
</head>
<body>
    <h1>Security Report</h1>
    <p>Generated: {{ generatedAt }}</p>

    <div class="summary">
        {{ summaryCards }}
    </div>

    <h2>Findings</h2>
    {{ findings }}
</body>
</html>
HTML;

        // Replace placeholders with actual content
        return $this->renderTemplate($template);
    }

    protected function generateMarkdown(): string
    {
        $md = "# Security Report\n\n";
        $md .= "**Generated:** {$this->metadata['generatedAt']}\n\n";

        $summary = $this->getSummary();
        $md .= "## Summary\n\n";
        $md .= "| Severity | Count |\n";
        $md .= "|----------|-------|\n";
        foreach ($summary['bySeverity'] as $severity => $count) {
            $md .= "| {$severity} | {$count} |\n";
        }

        $md .= "\n## Findings\n\n";

        foreach ($this->findings as $finding) {
            $md .= "### [{$finding->severity}] {$finding->title}\n\n";
            $md .= "**Category:** {$finding->category}\n\n";
            $md .= "{$finding->description}\n\n";

            if ($finding->remediation) {
                $md .= "**Remediation:** {$finding->remediation}\n\n";
            }

            $md .= "---\n\n";
        }

        return $md;
    }

    public function getSummary(): array
    {
        return [
            'total' => count($this->findings),
            'bySeverity' => [
                'critical' => $this->countBySeverity(['critical']),
                'high' => $this->countBySeverity(['high']),
                'medium' => $this->countBySeverity(['medium']),
                'low' => $this->countBySeverity(['low']),
                'info' => $this->countBySeverity(['info']),
            ],
            'byCategory' => $this->groupByCategory(),
        ];
    }

    protected function countBySeverity(array $severities): int
    {
        return count(array_filter(
            $this->findings,
            fn($f) => in_array($f->severity, $severities)
        ));
    }
}
```

### Phase 8: CI/CD Integration

#### 8.1 Security Pipeline Command

```php
<?php

namespace ArtisanPackUI\Security\Console\Commands;

use Illuminate\Console\Command;
use ArtisanPackUI\Security\Testing\Scanners\OwaspScanner;
use ArtisanPackUI\Security\Testing\Scanners\DependencyScanner;
use ArtisanPackUI\Security\Testing\Scanners\ConfigurationScanner;
use ArtisanPackUI\Security\Testing\Reporting\SecurityReportGenerator;

class SecurityScan extends Command
{
    protected $signature = 'security:scan
                            {--type=all : Type of scan (all, owasp, dependencies, config)}
                            {--format=json : Output format (json, html, sarif, junit, markdown)}
                            {--output= : Output file path}
                            {--fail-on=high : Fail on severity (critical, high, medium, low)}
                            {--baseline= : Path to baseline file for differential scanning}';

    protected $description = 'Run security scans and generate reports';

    public function handle(): int
    {
        $this->info('Starting security scan...');

        $findings = [];
        $type = $this->option('type');

        // Run scanners based on type
        if ($type === 'all' || $type === 'owasp') {
            $this->info('Running OWASP Top 10 scan...');
            $scanner = new OwaspScanner();
            $findings = array_merge($findings, $scanner->scan());
        }

        if ($type === 'all' || $type === 'dependencies') {
            $this->info('Running dependency scan...');
            $scanner = new DependencyScanner();
            $findings = array_merge($findings, $scanner->scan());
        }

        if ($type === 'all' || $type === 'config') {
            $this->info('Running configuration scan...');
            $scanner = new ConfigurationScanner();
            $findings = array_merge($findings, $scanner->scan());
        }

        // Apply baseline if provided
        if ($baseline = $this->option('baseline')) {
            $findings = $this->applyBaseline($findings, $baseline);
        }

        // Generate report
        $report = new SecurityReportGenerator(
            projectName: config('app.name'),
            version: config('app.version')
        );

        $report->addFindings($findings);
        $output = $report->generate($this->option('format'));

        // Output results
        if ($outputPath = $this->option('output')) {
            file_put_contents($outputPath, $output);
            $this->info("Report saved to: {$outputPath}");
        } else {
            $this->line($output);
        }

        // Display summary
        $this->displaySummary($report->getSummary());

        // Determine exit code based on findings
        return $this->determineExitCode($findings);
    }

    protected function displaySummary(array $summary): void
    {
        $this->newLine();
        $this->info('=== Scan Summary ===');

        $this->table(
            ['Severity', 'Count'],
            collect($summary['bySeverity'])->map(fn($count, $sev) => [$sev, $count])->toArray()
        );
    }

    protected function determineExitCode(array $findings): int
    {
        $failOn = $this->option('fail-on');
        $severityOrder = ['critical', 'high', 'medium', 'low', 'info'];
        $threshold = array_search($failOn, $severityOrder);

        foreach ($findings as $finding) {
            $findingSeverity = array_search($finding->severity, $severityOrder);
            if ($findingSeverity !== false && $findingSeverity <= $threshold) {
                $this->error("Scan failed: Found {$finding->severity} severity issue(s)");
                return 1;
            }
        }

        $this->info('Scan passed!');
        return 0;
    }

    protected function applyBaseline(array $findings, string $baselinePath): array
    {
        if (!file_exists($baselinePath)) {
            return $findings;
        }

        $baseline = json_decode(file_get_contents($baselinePath), true);
        $baselineIds = array_column($baseline['findings'] ?? [], 'id');

        // Filter out findings that are in the baseline
        return array_filter(
            $findings,
            fn($f) => !in_array($f->id, $baselineIds)
        );
    }
}
```

#### 8.2 GitHub Actions Integration

```php
<?php

namespace ArtisanPackUI\Security\Testing\CiCd;

class GitHubActionsIntegration
{
    /**
     * Output findings in GitHub Actions format.
     */
    public static function outputAnnotations(array $findings): void
    {
        foreach ($findings as $finding) {
            $level = match ($finding->severity) {
                'critical', 'high' => 'error',
                'medium' => 'warning',
                default => 'notice',
            };

            $location = $finding->location ?? '';
            $file = '';
            $line = '';

            if (preg_match('/^(.+):(\d+)/', $location, $matches)) {
                $file = $matches[1];
                $line = $matches[2];
            }

            echo "::{$level} file={$file},line={$line}::{$finding->title}: {$finding->description}\n";
        }
    }

    /**
     * Set output variables for GitHub Actions.
     */
    public static function setOutput(string $name, string $value): void
    {
        $output = getenv('GITHUB_OUTPUT');
        if ($output) {
            file_put_contents($output, "{$name}={$value}\n", FILE_APPEND);
        }
    }

    /**
     * Generate workflow file content.
     */
    public static function generateWorkflow(): string
    {
        return <<<'YAML'
name: Security Scan

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 0 * * 0'  # Weekly on Sunday

jobs:
  security-scan:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Setup PHP
        uses: shivammathur/setup-php@v2
        with:
          php-version: '8.2'

      - name: Install Dependencies
        run: composer install --no-progress

      - name: Run Security Scan
        run: php artisan security:scan --format=sarif --output=security-results.sarif --fail-on=high

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v2
        if: always()
        with:
          sarif_file: security-results.sarif

      - name: Dependency Scan
        run: php artisan security:scan --type=dependencies --format=json --output=dependencies.json

      - name: Upload Dependency Report
        uses: actions/upload-artifact@v4
        with:
          name: dependency-report
          path: dependencies.json
YAML;
    }
}
```

#### 8.3 Security Gate

```php
<?php

namespace ArtisanPackUI\Security\Testing\CiCd;

class SecurityGate
{
    protected array $rules = [];

    public function __construct(
        protected int $maxCritical = 0,
        protected int $maxHigh = 0,
        protected int $maxMedium = 10,
        protected float $maxOverheadPercent = 15.0,
    ) {}

    public function addRule(string $name, callable $check): self
    {
        $this->rules[$name] = $check;
        return $this;
    }

    public function evaluate(array $findings, ?array $benchmarks = null): GateResult
    {
        $failures = [];

        // Check severity thresholds
        $critical = $this->countBySeverity($findings, 'critical');
        $high = $this->countBySeverity($findings, 'high');
        $medium = $this->countBySeverity($findings, 'medium');

        if ($critical > $this->maxCritical) {
            $failures[] = "Critical findings ({$critical}) exceed threshold ({$this->maxCritical})";
        }

        if ($high > $this->maxHigh) {
            $failures[] = "High findings ({$high}) exceed threshold ({$this->maxHigh})";
        }

        if ($medium > $this->maxMedium) {
            $failures[] = "Medium findings ({$medium}) exceed threshold ({$this->maxMedium})";
        }

        // Check performance overhead
        if ($benchmarks) {
            foreach ($benchmarks as $benchmark) {
                if ($benchmark['overhead']['percent'] > $this->maxOverheadPercent) {
                    $failures[] = "Performance overhead for {$benchmark['name']} ({$benchmark['overhead']['percent']}%) exceeds threshold ({$this->maxOverheadPercent}%)";
                }
            }
        }

        // Run custom rules
        foreach ($this->rules as $name => $check) {
            $result = $check($findings, $benchmarks);
            if ($result !== true) {
                $failures[] = "Rule '{$name}' failed: {$result}";
            }
        }

        return new GateResult(
            passed: empty($failures),
            failures: $failures,
            summary: [
                'critical' => $critical,
                'high' => $high,
                'medium' => $medium,
            ]
        );
    }

    protected function countBySeverity(array $findings, string $severity): int
    {
        return count(array_filter($findings, fn($f) => $f->severity === $severity));
    }
}

class GateResult
{
    public function __construct(
        public readonly bool $passed,
        public readonly array $failures,
        public readonly array $summary,
    ) {}

    public function getExitCode(): int
    {
        return $this->passed ? 0 : 1;
    }
}
```

## Configuration

```php
// config/security.php - Add testing section

'testing' => [
    'enabled' => env('SECURITY_TESTING_ENABLED', true),

    /*
     * Scanner configuration
     */
    'scanners' => [
        'owasp' => [
            'enabled' => true,
            'categories' => ['A01', 'A02', 'A03', 'A04', 'A05', 'A06', 'A07', 'A08', 'A09', 'A10'],
        ],
        'dependencies' => [
            'enabled' => true,
            'composerLock' => base_path('composer.lock'),
            'packageLock' => base_path('package-lock.json'),
        ],
        'configuration' => [
            'enabled' => true,
        ],
    ],

    /*
     * Security gate thresholds for CI/CD
     */
    'gate' => [
        'maxCritical' => 0,
        'maxHigh' => 0,
        'maxMedium' => 10,
        'maxOverheadPercent' => 15.0,
    ],

    /*
     * Report settings
     */
    'reporting' => [
        'defaultFormat' => 'json',
        'outputPath' => storage_path('security-reports'),
        'retentionDays' => 90,
    ],

    /*
     * Baseline for differential scanning
     */
    'baseline' => [
        'path' => base_path('.security-baseline.json'),
        'autoUpdate' => false,
    ],
],
```

## Console Commands

| Command | Description |
|---------|-------------|
| `security:scan` | Run security scans |
| `security:audit` | Full security audit with all scanners |
| `security:benchmark` | Run performance benchmarks |
| `security:baseline` | Manage security baseline |

## Usage Examples

### Running Security Scans

```bash
# Full scan with JSON output
php artisan security:scan --format=json --output=report.json

# OWASP scan only
php artisan security:scan --type=owasp --fail-on=critical

# Dependency scan with SARIF output for GitHub
php artisan security:scan --type=dependencies --format=sarif --output=results.sarif

# Scan with baseline (ignore known issues)
php artisan security:scan --baseline=.security-baseline.json
```

### Writing Security Tests

```php
<?php

namespace Tests\Security;

use ArtisanPackUI\Security\Testing\SecurityTestCase;

class ApiSecurityTest extends SecurityTestCase
{
    public function test_login_not_vulnerable_to_sql_injection(): void
    {
        $this->assertNotVulnerableToSqlInjection(
            method: 'post',
            uri: '/api/login',
            parameters: ['email' => '', 'password' => ''],
            vulnerableParam: 'email'
        );
    }

    public function test_search_not_vulnerable_to_xss(): void
    {
        $this->assertNotVulnerableToXss(
            method: 'get',
            uri: '/search',
            parameters: ['q' => ''],
            vulnerableParam: 'q'
        );
    }

    public function test_file_download_not_vulnerable_to_path_traversal(): void
    {
        $this->assertNotVulnerableToPathTraversal(
            method: 'get',
            uri: '/download',
            parameters: ['file' => ''],
            vulnerableParam: 'file'
        );
    }
}
```

### Performance Benchmarking

```php
<?php

use ArtisanPackUI\Security\Testing\Performance\SecurityBenchmark;

$benchmark = new SecurityBenchmark();

// Benchmark middleware
$result = $benchmark->benchmarkMiddleware(ContentSecurityPolicy::class);

echo "CSP Middleware Overhead: {$result->getOverhead()}%\n";

// Benchmark validation rules
$result = $benchmark->benchmarkValidation('password_policy', 'TestPassword123!');

// Generate full report
$report = $benchmark->generateReport();
```

## Testing

The framework should include comprehensive tests:

- Unit tests for all scanners
- Unit tests for payload generators
- Unit tests for report formatters
- Integration tests for CI/CD integration
- Feature tests for console commands

## Dependencies

- PHP 8.2+
- Laravel 10.x/11.x
- PHPUnit/Pest for testing
- No external scanning services required (self-contained)

## Security Considerations

1. Payloads are for testing only - never use in production
2. Attack simulations should only run against test environments
3. Reports may contain sensitive information - handle appropriately
4. CI/CD tokens need minimal permissions
5. Baseline files should not suppress critical findings indefinitely
