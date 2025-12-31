# Compliance Framework Implementation Plan

## Overview

This document outlines the implementation plan for a comprehensive compliance framework supporting GDPR, CCPA, and other privacy regulations in the ArtisanPack Security package. The goal is to provide tools for data protection impact assessments, privacy by design, consent management, and automated compliance monitoring.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Data Protection Impact Assessment Tools](#data-protection-impact-assessment-tools)
3. [Privacy by Design Implementation](#privacy-by-design-implementation)
4. [Data Minimization Utilities](#data-minimization-utilities)
5. [Right to Be Forgotten Implementation](#right-to-be-forgotten-implementation)
6. [Data Portability Features](#data-portability-features)
7. [Consent Management System](#consent-management-system)
8. [Compliance Reporting Dashboard](#compliance-reporting-dashboard)
9. [Automated Compliance Checking](#automated-compliance-checking)
10. [Database Schema](#database-schema)
11. [Configuration](#configuration)
12. [File Structure](#file-structure)
13. [Implementation Order](#implementation-order)

---

## Architecture Overview

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        Laravel Application                               │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐                   │
│  │   Models     │  │  Middleware  │  │   Events     │                   │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘                   │
│         │                 │                 │                            │
│         └─────────────────┼─────────────────┘                            │
│                           ▼                                              │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │                  Compliance Framework Pipeline                   │    │
│  │  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌───────────────┐│    │
│  │  │  Consent   │ │   Data     │ │  Privacy   │ │  Compliance   ││    │
│  │  │  Manager   │ │  Subject   │ │  Assessor  │ │   Monitor     ││    │
│  │  └────────────┘ └────────────┘ └────────────┘ └───────────────┘│    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                           │                                              │
│         ┌─────────────────┼─────────────────┐                            │
│         ▼                 ▼                 ▼                            │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐                   │
│  │   Database   │  │    Cache     │  │    Queue     │                   │
│  └──────────────┘  └──────────────┘  └──────────────┘                   │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                      External Integrations                               │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────────────┐   │
│  │   Data     │ │  Export    │ │  Audit     │ │    Regulatory      │   │
│  │  Subjects  │ │  Formats   │ │  Logging   │ │    Authorities     │   │
│  └────────────┘ └────────────┘ └────────────┘ └────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
```

### Core Components

1. **Consent Manager** - Handles consent collection, storage, and verification
2. **Data Subject Handler** - Processes data subject requests (access, erasure, portability)
3. **Privacy Assessor** - Conducts data protection impact assessments
4. **Data Minimizer** - Enforces data minimization and retention policies
5. **Compliance Monitor** - Automated compliance checking and reporting
6. **Privacy Registry** - Maintains processing activity records

### Supported Regulations

| Regulation | Region | Key Requirements |
|------------|--------|------------------|
| GDPR | EU/EEA | Consent, Right to Erasure, Data Portability, DPIAs |
| CCPA/CPRA | California | Right to Know, Right to Delete, Opt-Out of Sale |
| LGPD | Brazil | Consent, Data Subject Rights, DPO Requirements |
| PIPEDA | Canada | Consent, Access Rights, Accountability |
| POPIA | South Africa | Lawful Processing, Data Subject Rights |
| PDPA | Singapore | Consent, Access and Correction, Data Protection |

---

## Data Protection Impact Assessment Tools

### Overview

Data Protection Impact Assessments (DPIAs) are mandatory under GDPR Article 35 for high-risk processing activities. This module provides tools to conduct, document, and manage DPIAs.

### Features

1. **Assessment Templates** - Pre-built templates for common processing activities
2. **Risk Scoring Engine** - Automated risk calculation based on GDPR criteria
3. **Stakeholder Collaboration** - Multi-user assessment workflow
4. **Mitigation Tracking** - Track risk mitigation measures
5. **Regulatory Integration** - Export to authority-required formats
6. **Version Control** - Track assessment revisions

### Risk Categories

| Category | Description | Weight |
|----------|-------------|--------|
| Data Volume | Number of data subjects affected | 1-5 |
| Data Sensitivity | Special categories of personal data | 1-5 |
| Processing Purpose | Purpose and necessity of processing | 1-5 |
| Automated Decisions | Profiling or automated decision-making | 1-5 |
| Cross-Border Transfer | International data transfers | 1-5 |
| Vulnerable Subjects | Children, employees, patients | 1-5 |
| Innovation Level | New technologies or approaches | 1-5 |
| Systematic Monitoring | Large-scale systematic monitoring | 1-5 |

### Implementation

#### DpiaService

```php
namespace ArtisanPackUI\Security\Compliance\Assessment;

class DpiaService
{
    // Create a new DPIA assessment
    public function createAssessment(array $data): DataProtectionAssessment;

    // Calculate risk score for an assessment
    public function calculateRiskScore(DataProtectionAssessment $assessment): RiskScore;

    // Add a risk to the assessment
    public function addRisk(DataProtectionAssessment $assessment, array $riskData): AssessmentRisk;

    // Add a mitigation measure
    public function addMitigation(AssessmentRisk $risk, array $mitigationData): RiskMitigation;

    // Check if DPIA is required for processing activity
    public function isRequired(ProcessingActivity $activity): bool;

    // Get assessment by processing activity
    public function getForActivity(ProcessingActivity $activity): ?DataProtectionAssessment;

    // Submit assessment for review
    public function submitForReview(DataProtectionAssessment $assessment): void;

    // Approve/reject assessment
    public function review(DataProtectionAssessment $assessment, string $decision, ?string $notes = null): void;

    // Export assessment to PDF/Word
    public function export(DataProtectionAssessment $assessment, string $format = 'pdf'): string;

    // Clone assessment for revision
    public function createRevision(DataProtectionAssessment $assessment): DataProtectionAssessment;
}
```

#### RiskAssessor

```php
namespace ArtisanPackUI\Security\Compliance\Assessment;

class RiskAssessor
{
    // Calculate overall risk level
    public function calculateOverallRisk(array $risks): RiskLevel;

    // Assess data sensitivity risk
    public function assessDataSensitivity(array $dataCategories): int;

    // Assess processing purpose risk
    public function assessProcessingPurpose(string $purpose, array $legalBases): int;

    // Assess automated decision-making risk
    public function assessAutomation(bool $hasAutomatedDecisions, bool $hasProfiling): int;

    // Assess cross-border transfer risk
    public function assessTransferRisk(array $countries): int;

    // Assess vulnerable subjects risk
    public function assessVulnerableSubjects(array $subjectCategories): int;

    // Get recommended mitigations for risk type
    public function getRecommendedMitigations(string $riskType): array;

    // Validate assessment completeness
    public function validateCompleteness(DataProtectionAssessment $assessment): array;
}
```

#### DataProtectionAssessment Model

```php
namespace ArtisanPackUI\Security\Models;

class DataProtectionAssessment extends Model
{
    protected $fillable = [
        'assessment_number',        // Auto-generated: DPIA-2025-000001
        'title',
        'description',
        'processing_activity_id',
        'status',                   // draft, in_review, approved, rejected, revision_required
        'version',
        'parent_assessment_id',     // For revisions
        'data_categories',          // JSON: categories of personal data
        'data_subjects',            // JSON: categories of data subjects
        'processing_purposes',      // JSON: purposes of processing
        'legal_bases',              // JSON: legal bases for processing
        'recipients',               // JSON: data recipients
        'retention_periods',        // JSON: retention periods by data type
        'transfers',                // JSON: international transfers
        'security_measures',        // JSON: technical/organizational measures
        'overall_risk_score',
        'overall_risk_level',       // low, medium, high, critical
        'dpo_opinion',
        'dpo_reviewed_at',
        'dpo_reviewed_by',
        'created_by',
        'reviewed_by',
        'approved_at',
        'next_review_at',
    ];

    protected $casts = [
        'data_categories' => 'array',
        'data_subjects' => 'array',
        'processing_purposes' => 'array',
        'legal_bases' => 'array',
        'recipients' => 'array',
        'retention_periods' => 'array',
        'transfers' => 'array',
        'security_measures' => 'array',
        'approved_at' => 'datetime',
        'next_review_at' => 'datetime',
        'dpo_reviewed_at' => 'datetime',
    ];
}
```

#### AssessmentRisk Model

```php
namespace ArtisanPackUI\Security\Models;

class AssessmentRisk extends Model
{
    protected $fillable = [
        'assessment_id',
        'risk_category',            // data_volume, sensitivity, automation, etc.
        'risk_title',
        'risk_description',
        'likelihood',               // rare, unlikely, possible, likely, almost_certain
        'impact',                   // negligible, minor, moderate, major, severe
        'inherent_score',           // Score before mitigations
        'residual_score',           // Score after mitigations
        'risk_level',               // low, medium, high, critical
        'risk_owner',
        'status',                   // identified, mitigating, mitigated, accepted
        'accepted_by',
        'accepted_at',
        'acceptance_justification',
    ];
}
```

#### RiskMitigation Model

```php
namespace ArtisanPackUI\Security\Models;

class RiskMitigation extends Model
{
    protected $fillable = [
        'risk_id',
        'title',
        'description',
        'type',                     // technical, organizational, contractual
        'status',                   // planned, in_progress, implemented, verified
        'priority',                 // low, medium, high, critical
        'assigned_to',
        'due_date',
        'implemented_at',
        'verified_at',
        'verified_by',
        'effectiveness_rating',     // 1-5
        'notes',
    ];
}
```

---

## Privacy by Design Implementation

### Overview

Privacy by Design (PbD) is a foundational principle under GDPR requiring privacy to be embedded into system design. This module provides tools, traits, and middleware for implementing PbD principles.

### Seven Foundational Principles

1. **Proactive not Reactive** - Prevent privacy issues before they occur
2. **Privacy as Default** - Maximum privacy without user action
3. **Privacy Embedded** - Built into design, not bolted on
4. **Full Functionality** - No trade-offs between privacy and functionality
5. **End-to-End Security** - Lifecycle data protection
6. **Visibility/Transparency** - Open and verifiable
7. **User-Centric** - Respect for user privacy

### Implementation

#### PrivacyByDesign Trait

```php
namespace ArtisanPackUI\Security\Compliance\Traits;

trait PrivacyByDesign
{
    // Define which attributes contain personal data
    protected function getPersonalDataAttributes(): array;

    // Define which attributes are sensitive/special category
    protected function getSensitiveDataAttributes(): array;

    // Get data minimization rules
    protected function getMinimizationRules(): array;

    // Get retention periods for attributes
    protected function getRetentionPeriods(): array;

    // Automatically encrypt sensitive attributes
    protected function encryptSensitiveData(): void;

    // Pseudonymize personal data for analytics
    public function pseudonymize(): array;

    // Get anonymized copy of the model
    public function anonymize(): array;

    // Check if data can be collected for purpose
    public function canCollectFor(string $purpose): bool;

    // Log data access for audit trail
    protected function logDataAccess(string $accessor, string $purpose): void;
}
```

#### DataMinimizationValidator

```php
namespace ArtisanPackUI\Security\Compliance\Validation;

class DataMinimizationValidator
{
    // Validate that only necessary data is collected
    public function validateCollection(array $data, string $purpose): ValidationResult;

    // Get fields allowed for purpose
    public function getAllowedFields(string $purpose): array;

    // Get fields required for purpose
    public function getRequiredFields(string $purpose): array;

    // Check if field is necessary for purpose
    public function isNecessary(string $field, string $purpose): bool;

    // Validate data against minimization rules
    public function validate(array $data, array $rules): array;
}
```

#### PrivacyMiddleware

```php
namespace ArtisanPackUI\Security\Compliance\Middleware;

class PrivacyMiddleware
{
    // Check consent before processing
    public function checkConsent(Request $request, string $purpose): bool;

    // Apply data minimization to response
    public function minimizeResponse(Response $response, string $purpose): Response;

    // Add privacy headers to response
    public function addPrivacyHeaders(Response $response): Response;

    // Log processing activity
    public function logProcessingActivity(Request $request, string $purpose): void;
}
```

#### PrivacyAwareModel Base Class

```php
namespace ArtisanPackUI\Security\Compliance\Models;

abstract class PrivacyAwareModel extends Model
{
    use PrivacyByDesign;

    // Automatically log all data access
    protected static bool $logDataAccess = true;

    // Automatically encrypt sensitive fields
    protected static bool $autoEncryptSensitive = true;

    // Retention period in days (null = indefinite)
    protected ?int $retentionDays = null;

    // Override boot to add privacy observers
    protected static function bootPrivacyAwareModel(): void;

    // Get lawful basis for processing
    public function getLawfulBasis(): string;

    // Check if retention period has expired
    public function isRetentionExpired(): bool;

    // Get time until retention expires
    public function getRetentionRemaining(): ?CarbonInterval;

    // Scope for data past retention period
    public function scopeExpiredRetention($query);

    // Get audit trail for this record
    public function getAuditTrail(): Collection;
}
```

#### ProcessingActivity Model

```php
namespace ArtisanPackUI\Security\Models;

class ProcessingActivity extends Model
{
    protected $fillable = [
        'name',
        'description',
        'controller_name',          // Data controller details
        'controller_contact',
        'processor_name',           // Data processor (if applicable)
        'processor_contact',
        'dpo_contact',
        'purposes',                 // JSON: processing purposes
        'legal_bases',              // JSON: legal bases per purpose
        'data_categories',          // JSON: categories of data processed
        'data_subjects',            // JSON: categories of data subjects
        'recipients',               // JSON: recipients of data
        'third_countries',          // JSON: international transfers
        'safeguards',               // JSON: transfer safeguards
        'retention_policy',         // JSON: retention periods
        'security_measures',        // JSON: technical/organizational measures
        'automated_decisions',      // JSON: automated decision-making details
        'dpia_required',
        'dpia_reference',
        'status',                   // active, suspended, terminated
        'last_review_at',
        'next_review_at',
    ];

    protected $casts = [
        'purposes' => 'array',
        'legal_bases' => 'array',
        'data_categories' => 'array',
        'data_subjects' => 'array',
        'recipients' => 'array',
        'third_countries' => 'array',
        'safeguards' => 'array',
        'retention_policy' => 'array',
        'security_measures' => 'array',
        'automated_decisions' => 'array',
        'dpia_required' => 'boolean',
        'last_review_at' => 'datetime',
        'next_review_at' => 'datetime',
    ];
}
```

---

## Data Minimization Utilities

### Overview

Data minimization is a core GDPR principle requiring organizations to collect only data necessary for specified purposes. This module provides utilities for enforcing data minimization policies.

### Features

1. **Collection Policies** - Define what data can be collected for each purpose
2. **Retention Policies** - Automatic enforcement of retention periods
3. **Anonymization Tools** - Transform data for analytics while preserving privacy
4. **Pseudonymization Tools** - Replace identifiers with pseudonyms
5. **Data Reduction** - Periodically reduce stored data to minimum
6. **Purpose Limitation** - Enforce data use only for specified purposes

### Implementation

#### DataMinimizerService

```php
namespace ArtisanPackUI\Security\Compliance\Minimization;

class DataMinimizerService
{
    // Apply collection policy to incoming data
    public function applyCollectionPolicy(array $data, string $purpose): array;

    // Check if data collection is compliant
    public function validateCollection(array $data, string $purpose): ValidationResult;

    // Anonymize dataset
    public function anonymize(Collection $data, array $fields): Collection;

    // Pseudonymize dataset
    public function pseudonymize(Collection $data, array $fields): PseudonymizedResult;

    // Reverse pseudonymization (with authorization)
    public function dePseudonymize(string $pseudonym, string $field): ?string;

    // Get data that has exceeded retention period
    public function getExpiredData(string $model): Collection;

    // Purge expired data
    public function purgeExpiredData(string $model): int;

    // Get collection policy for purpose
    public function getCollectionPolicy(string $purpose): CollectionPolicy;

    // Register a collection policy
    public function registerPolicy(string $purpose, CollectionPolicy $policy): void;
}
```

#### AnonymizationEngine

```php
namespace ArtisanPackUI\Security\Compliance\Minimization;

class AnonymizationEngine
{
    // Anonymize a single value
    public function anonymizeValue($value, string $type): mixed;

    // Available anonymization strategies
    public function getStrategies(): array;

    // Generalize a value (k-anonymity)
    public function generalize($value, string $type, int $level = 1): mixed;

    // Suppress a value (remove completely)
    public function suppress($value): null;

    // Add noise for differential privacy
    public function addNoise(float $value, float $epsilon): float;

    // Hash with salt for pseudonymization
    public function hash(string $value, string $salt): string;

    // Tokenize (reversible with key)
    public function tokenize(string $value): string;

    // Mask partial data (e.g., ****@example.com)
    public function mask(string $value, string $type): string;

    // Validate k-anonymity of dataset
    public function validateKAnonymity(Collection $data, array $quasiIdentifiers, int $k): bool;
}
```

#### RetentionPolicy Model

```php
namespace ArtisanPackUI\Security\Models;

class RetentionPolicy extends Model
{
    protected $fillable = [
        'name',
        'description',
        'model_class',              // Laravel model this applies to
        'data_category',            // Category of data
        'retention_days',           // Days to retain (null = indefinite)
        'legal_basis',              // Legal basis for retention
        'deletion_strategy',        // delete, anonymize, archive
        'archive_location',         // If archiving, where
        'conditions',               // JSON: conditions for retention
        'exceptions',               // JSON: exception criteria
        'notification_days',        // Days before expiry to notify
        'is_active',
        'created_by',
    ];

    protected $casts = [
        'conditions' => 'array',
        'exceptions' => 'array',
        'is_active' => 'boolean',
    ];
}
```

#### CollectionPolicy Model

```php
namespace ArtisanPackUI\Security\Models;

class CollectionPolicy extends Model
{
    protected $fillable = [
        'name',
        'purpose',                  // Processing purpose
        'allowed_fields',           // JSON: fields allowed for this purpose
        'required_fields',          // JSON: fields required for this purpose
        'conditional_fields',       // JSON: fields conditionally allowed
        'prohibited_fields',        // JSON: fields never allowed
        'legal_basis',
        'consent_type',             // explicit, implied, not_required
        'minimization_rules',       // JSON: specific rules
        'is_active',
    ];

    protected $casts = [
        'allowed_fields' => 'array',
        'required_fields' => 'array',
        'conditional_fields' => 'array',
        'prohibited_fields' => 'array',
        'minimization_rules' => 'array',
        'is_active' => 'boolean',
    ];
}
```

---

## Right to Be Forgotten Implementation

### Overview

The Right to Erasure (Right to Be Forgotten) under GDPR Article 17 requires organizations to delete personal data upon request. This module handles erasure requests with proper verification, cascading deletions, and audit trails.

### Features

1. **Request Management** - Submit, track, and process erasure requests
2. **Identity Verification** - Verify requester identity before processing
3. **Cascading Deletion** - Delete data across all systems/tables
4. **Third-Party Notification** - Notify data recipients of erasure
5. **Exemption Handling** - Handle legal exemptions to erasure
6. **Proof of Deletion** - Generate deletion certificates
7. **Partial Erasure** - Handle cases where full erasure isn't possible

### Exemptions (GDPR Article 17(3))

- Exercise of freedom of expression
- Legal obligation compliance
- Public health reasons
- Archiving in public interest
- Establishment/defense of legal claims

### Implementation

#### ErasureService

```php
namespace ArtisanPackUI\Security\Compliance\Erasure;

class ErasureService
{
    // Submit an erasure request
    public function submitRequest(int $userId, array $options = []): ErasureRequest;

    // Verify requester identity
    public function verifyIdentity(ErasureRequest $request, array $verificationData): bool;

    // Process an approved erasure request
    public function processRequest(ErasureRequest $request): ErasureResult;

    // Check for exemptions
    public function checkExemptions(ErasureRequest $request): array;

    // Execute deletion across all registered handlers
    public function executeErasure(int $userId, array $options = []): ErasureResult;

    // Notify third parties of erasure
    public function notifyRecipients(ErasureRequest $request): array;

    // Generate proof of deletion certificate
    public function generateCertificate(ErasureRequest $request): string;

    // Register a custom erasure handler
    public function registerHandler(string $name, ErasureHandlerInterface $handler): void;

    // Get all registered handlers
    public function getHandlers(): array;

    // Rollback erasure (within grace period)
    public function rollback(ErasureRequest $request): bool;
}
```

#### ErasureHandlerInterface

```php
namespace ArtisanPackUI\Security\Compliance\Contracts;

interface ErasureHandlerInterface
{
    // Get handler name
    public function getName(): string;

    // Get handler description
    public function getDescription(): string;

    // Check if handler can process erasure for user
    public function canHandle(int $userId): bool;

    // Find all data for user
    public function findUserData(int $userId): Collection;

    // Execute erasure
    public function erase(int $userId, array $options = []): ErasureHandlerResult;

    // Check if erasure is reversible
    public function isReversible(): bool;

    // Rollback erasure if possible
    public function rollback(int $userId, array $backupData): bool;

    // Get estimated time to complete
    public function getEstimatedTime(): int;

    // Get data categories handled
    public function getDataCategories(): array;
}
```

#### Built-in Erasure Handlers

```php
// Core handlers
UserDataErasureHandler::class          // Main user table
ProfileDataErasureHandler::class       // Profile information
ConsentDataErasureHandler::class       // Consent records
AuditLogErasureHandler::class          // Audit logs (may be exempt)
SessionDataErasureHandler::class       // Active sessions
TokenDataErasureHandler::class         // API tokens
NotificationErasureHandler::class      // Notifications
ActivityLogErasureHandler::class       // Activity history

// Analytics handlers
MetricsErasureHandler::class           // User-related metrics
BehaviorProfileErasureHandler::class   // Behavior profiles
AnomalyErasureHandler::class           // User anomaly records

// Custom handler registration
$erasureService->registerHandler('custom', new CustomErasureHandler());
```

#### ErasureRequest Model

```php
namespace ArtisanPackUI\Security\Models;

class ErasureRequest extends Model
{
    protected $fillable = [
        'request_number',           // Auto-generated: ERA-2025-000001
        'user_id',
        'requester_type',           // self, guardian, authorized_agent
        'requester_contact',
        'status',                   // pending, verifying, approved, processing, completed, rejected
        'scope',                    // full, partial
        'specific_data',            // JSON: specific data to erase if partial
        'reason',
        'identity_verified',
        'identity_verified_at',
        'identity_verified_method',
        'exemptions_found',         // JSON: any exemptions that apply
        'exemption_explanation',
        'handlers_processed',       // JSON: handlers that ran
        'handlers_failed',          // JSON: handlers that failed
        'third_parties_notified',   // JSON: third parties notified
        'certificate_path',         // Path to deletion certificate
        'completed_at',
        'rejected_at',
        'rejected_by',
        'rejection_reason',
        'deadline_at',              // Legal deadline (usually 30 days)
        'created_by',
        'processed_by',
    ];

    protected $casts = [
        'specific_data' => 'array',
        'exemptions_found' => 'array',
        'handlers_processed' => 'array',
        'handlers_failed' => 'array',
        'third_parties_notified' => 'array',
        'identity_verified' => 'boolean',
        'identity_verified_at' => 'datetime',
        'completed_at' => 'datetime',
        'rejected_at' => 'datetime',
        'deadline_at' => 'datetime',
    ];
}
```

#### ErasureLog Model

```php
namespace ArtisanPackUI\Security\Models;

class ErasureLog extends Model
{
    protected $fillable = [
        'request_id',
        'handler_name',
        'action',                   // find, erase, verify, rollback
        'status',                   // success, failed, skipped
        'records_found',
        'records_erased',
        'records_retained',         // Due to exemptions
        'retention_reason',
        'backup_reference',         // Reference to backup if reversible
        'error_message',
        'metadata',                 // JSON: additional details
        'started_at',
        'completed_at',
    ];

    protected $casts = [
        'metadata' => 'array',
        'started_at' => 'datetime',
        'completed_at' => 'datetime',
    ];
}
```

---

## Data Portability Features

### Overview

The Right to Data Portability under GDPR Article 20 requires organizations to provide personal data in a structured, commonly used, machine-readable format. This module handles data export requests and format conversion.

### Features

1. **Export Formats** - JSON, XML, CSV with standardized schemas
2. **Selective Export** - Export specific data categories
3. **Direct Transfer** - Transfer data directly to another controller
4. **Streaming Export** - Handle large datasets efficiently
5. **Export Scheduling** - Schedule recurring exports
6. **Format Validation** - Validate exported data against schemas

### Supported Formats

| Format | Use Case | Standard |
|--------|----------|----------|
| JSON | General purpose, APIs | JSON Schema |
| XML | Enterprise systems | XML Schema |
| CSV | Spreadsheets, databases | RFC 4180 |
| JSON-LD | Linked data, semantic web | W3C |

### Implementation

#### PortabilityService

```php
namespace ArtisanPackUI\Security\Compliance\Portability;

class PortabilityService
{
    // Submit a portability request
    public function submitRequest(int $userId, array $options = []): PortabilityRequest;

    // Process a portability request
    public function processRequest(PortabilityRequest $request): PortabilityResult;

    // Export user data to specified format
    public function export(int $userId, string $format = 'json', array $categories = []): ExportResult;

    // Export user data as stream (for large datasets)
    public function exportStream(int $userId, string $format = 'json'): StreamedResponse;

    // Transfer data directly to another controller
    public function transferTo(int $userId, string $destinationUrl, array $credentials): TransferResult;

    // Validate exported data against schema
    public function validateExport(string $data, string $format): ValidationResult;

    // Register a custom data exporter
    public function registerExporter(string $name, DataExporterInterface $exporter): void;

    // Get available export formats
    public function getFormats(): array;

    // Get exportable data categories
    public function getCategories(): array;

    // Estimate export size
    public function estimateSize(int $userId, array $categories = []): int;
}
```

#### DataExporterInterface

```php
namespace ArtisanPackUI\Security\Compliance\Contracts;

interface DataExporterInterface
{
    // Get exporter name
    public function getName(): string;

    // Get data category
    public function getCategory(): string;

    // Get exportable data for user
    public function getData(int $userId): Collection;

    // Get data schema
    public function getSchema(): array;

    // Transform data for export
    public function transform(Collection $data): array;

    // Get supported formats
    public function getSupportedFormats(): array;

    // Get estimated record count
    public function getRecordCount(int $userId): int;
}
```

#### Built-in Data Exporters

```php
// Core exporters
UserDataExporter::class              // Basic user information
ProfileDataExporter::class           // Profile details
ConsentHistoryExporter::class        // Consent records
ActivityDataExporter::class          // User activity
PreferencesExporter::class           // User preferences
CommunicationsExporter::class        // Communication history
DocumentsExporter::class             // User documents
TransactionsExporter::class          // Transactions (if applicable)

// Security exporters
SessionHistoryExporter::class        // Session history
SecurityEventsExporter::class        // Security events
AuditTrailExporter::class            // Audit trail
```

#### PortabilityRequest Model

```php
namespace ArtisanPackUI\Security\Models;

class PortabilityRequest extends Model
{
    protected $fillable = [
        'request_number',           // Auto-generated: POR-2025-000001
        'user_id',
        'requester_type',           // self, guardian, authorized_agent
        'status',                   // pending, processing, completed, failed, expired
        'format',                   // json, xml, csv
        'categories',               // JSON: data categories to export
        'transfer_type',            // download, direct_transfer
        'destination_url',          // For direct transfers
        'destination_verified',
        'file_path',                // Path to exported file
        'file_size',
        'file_hash',                // SHA-256 hash for integrity
        'download_count',
        'download_limit',           // Max downloads allowed
        'expires_at',               // Download link expiry
        'completed_at',
        'downloaded_at',
        'deadline_at',              // Legal deadline
        'created_by',
    ];

    protected $casts = [
        'categories' => 'array',
        'destination_verified' => 'boolean',
        'expires_at' => 'datetime',
        'completed_at' => 'datetime',
        'downloaded_at' => 'datetime',
        'deadline_at' => 'datetime',
    ];
}
```

#### ExportSchema Model

```php
namespace ArtisanPackUI\Security\Models;

class ExportSchema extends Model
{
    protected $fillable = [
        'name',
        'category',
        'version',
        'format',                   // json, xml
        'schema_definition',        // JSON/XML schema
        'field_mappings',           // JSON: internal to export field mappings
        'transformations',          // JSON: data transformations
        'is_default',
        'is_active',
    ];

    protected $casts = [
        'schema_definition' => 'array',
        'field_mappings' => 'array',
        'transformations' => 'array',
        'is_default' => 'boolean',
        'is_active' => 'boolean',
    ];
}
```

---

## Consent Management System

### Overview

The Consent Management System handles the collection, storage, verification, and withdrawal of user consent as required by GDPR and other regulations. It provides granular consent options and maintains a complete audit trail.

### Features

1. **Granular Consent** - Purpose-specific consent options
2. **Consent Versioning** - Track consent policy versions
3. **Withdrawal Mechanism** - Easy consent withdrawal
4. **Consent Verification** - API to verify consent status
5. **Audit Trail** - Complete history of consent changes
6. **Cookie Consent** - Integration with cookie management
7. **Consent Analytics** - Reports on consent rates
8. **Multi-Channel** - Web, mobile, API consent collection

### Consent Types

| Type | Description | Legal Basis |
|------|-------------|-------------|
| Explicit | Active opt-in required | GDPR Art. 6(1)(a) |
| Implied | Based on user action | GDPR Art. 6(1)(b) |
| Bundled | Multiple purposes together | Not GDPR compliant |
| Granular | Separate per purpose | GDPR compliant |

### Implementation

#### ConsentManager Service

```php
namespace ArtisanPackUI\Security\Compliance\Consent;

class ConsentManager
{
    // Record a consent grant
    public function grant(int $userId, string $purpose, array $options = []): ConsentRecord;

    // Withdraw consent
    public function withdraw(int $userId, string $purpose, ?string $reason = null): bool;

    // Check if consent is valid for purpose
    public function hasConsent(int $userId, string $purpose): bool;

    // Get all consents for user
    public function getConsents(int $userId): Collection;

    // Get consent status for multiple purposes
    public function getConsentStatus(int $userId, array $purposes): array;

    // Get consent history for user
    public function getHistory(int $userId, ?string $purpose = null): Collection;

    // Update consent policy version
    public function updatePolicyVersion(string $purpose, string $version, array $changes): ConsentPolicy;

    // Get users who need to reconsent
    public function getUsersRequiringReconsent(string $purpose): Collection;

    // Send reconsent notifications
    public function notifyReconsent(string $purpose): int;

    // Export consent records for user
    public function exportConsents(int $userId): array;

    // Verify consent is valid (not expired, policy not changed)
    public function verifyConsent(int $userId, string $purpose): ConsentVerification;

    // Get consent statistics
    public function getStatistics(?string $purpose = null): array;
}
```

#### ConsentPolicyService

```php
namespace ArtisanPackUI\Security\Compliance\Consent;

class ConsentPolicyService
{
    // Create a new consent policy
    public function create(array $data): ConsentPolicy;

    // Update policy (creates new version)
    public function update(ConsentPolicy $policy, array $changes): ConsentPolicy;

    // Get active policy for purpose
    public function getActive(string $purpose): ?ConsentPolicy;

    // Get all versions of a policy
    public function getVersions(string $purpose): Collection;

    // Compare two policy versions
    public function compare(ConsentPolicy $v1, ConsentPolicy $v2): array;

    // Check if policy change requires reconsent
    public function requiresReconsent(ConsentPolicy $oldPolicy, ConsentPolicy $newPolicy): bool;

    // Deactivate a policy
    public function deactivate(ConsentPolicy $policy): void;

    // Get policies requiring user consent
    public function getRequiredPolicies(): Collection;
}
```

#### ConsentRecord Model

```php
namespace ArtisanPackUI\Security\Models;

class ConsentRecord extends Model
{
    protected $fillable = [
        'user_id',
        'purpose',                  // marketing, analytics, personalization, etc.
        'policy_id',
        'policy_version',
        'status',                   // granted, withdrawn, expired
        'consent_type',             // explicit, implied
        'collection_method',        // web_form, api, mobile_app, verbal, written
        'collection_context',       // JSON: page, campaign, etc.
        'ip_address',
        'user_agent',
        'proof_reference',          // Reference to proof of consent
        'granular_choices',         // JSON: sub-choices within purpose
        'expires_at',
        'withdrawn_at',
        'withdrawal_reason',
        'metadata',                 // JSON: additional context
    ];

    protected $casts = [
        'collection_context' => 'array',
        'granular_choices' => 'array',
        'metadata' => 'array',
        'expires_at' => 'datetime',
        'withdrawn_at' => 'datetime',
    ];
}
```

#### ConsentPolicy Model

```php
namespace ArtisanPackUI\Security\Models;

class ConsentPolicy extends Model
{
    protected $fillable = [
        'purpose',                  // Unique identifier for purpose
        'name',                     // Display name
        'description',              // Full description
        'legal_text',               // Legal consent text
        'version',
        'previous_version_id',
        'data_categories',          // JSON: what data is collected
        'processing_details',       // JSON: how data is processed
        'retention_period',         // How long data is kept
        'third_party_sharing',      // JSON: third parties data is shared with
        'rights_description',       // Description of user rights
        'withdrawal_consequences',  // What happens on withdrawal
        'is_required',              // Whether consent is required for service
        'is_active',
        'requires_explicit',        // Requires explicit opt-in
        'minimum_age',              // Minimum age for consent
        'effective_at',
        'expires_at',
        'changes_from_previous',    // JSON: what changed from previous version
        'created_by',
    ];

    protected $casts = [
        'data_categories' => 'array',
        'processing_details' => 'array',
        'third_party_sharing' => 'array',
        'changes_from_previous' => 'array',
        'is_required' => 'boolean',
        'is_active' => 'boolean',
        'requires_explicit' => 'boolean',
        'effective_at' => 'datetime',
        'expires_at' => 'datetime',
    ];
}
```

#### ConsentAuditLog Model

```php
namespace ArtisanPackUI\Security\Models;

class ConsentAuditLog extends Model
{
    protected $fillable = [
        'consent_record_id',
        'user_id',
        'action',                   // granted, withdrawn, expired, policy_updated
        'purpose',
        'old_status',
        'new_status',
        'policy_version',
        'actor_type',               // user, system, admin
        'actor_id',
        'reason',
        'ip_address',
        'user_agent',
        'metadata',                 // JSON: additional context
    ];

    protected $casts = [
        'metadata' => 'array',
    ];
}
```

### Consent Widget Integration

```php
// Blade component for consent banner
<x-compliance-consent-banner
    :purposes="['analytics', 'marketing', 'personalization']"
    :required="['essential']"
    position="bottom"
    theme="dark"
/>

// JavaScript API
ConsentManager.show();
ConsentManager.grant('analytics');
ConsentManager.withdraw('marketing');
ConsentManager.hasConsent('analytics'); // returns boolean
ConsentManager.getChoices(); // returns object of all choices
```

---

## Compliance Reporting Dashboard

### Overview

The Compliance Reporting Dashboard provides real-time visibility into compliance status, data subject requests, consent metrics, and regulatory readiness. It supports multiple reporting formats for different audiences.

### Features

1. **Compliance Overview** - At-a-glance compliance status
2. **Request Tracking** - DSR status and metrics
3. **Consent Analytics** - Consent rates and trends
4. **DPIA Status** - Assessment completion tracking
5. **Risk Heat Map** - Visual risk representation
6. **Regulatory Reports** - Pre-built regulatory reports
7. **Custom Reports** - Build custom compliance reports
8. **Scheduled Reports** - Automated report generation

### Dashboard Widgets

| Widget | Description |
|--------|-------------|
| Compliance Score | Overall compliance rating |
| DSR Status | Data subject request summary |
| Consent Metrics | Consent rates by purpose |
| DPIA Progress | Assessment completion status |
| Risk Overview | Risk level distribution |
| Processing Activities | Active processing summary |
| Retention Compliance | Data past retention period |
| Breach Timeline | Recent breach incidents |

### Implementation

#### ComplianceDashboardService

```php
namespace ArtisanPackUI\Security\Compliance\Reporting;

class ComplianceDashboardService
{
    // Get overall compliance score
    public function getComplianceScore(): ComplianceScore;

    // Get dashboard summary
    public function getSummary(): array;

    // Get DSR metrics
    public function getDsrMetrics(Carbon $from, Carbon $to): array;

    // Get consent metrics
    public function getConsentMetrics(): array;

    // Get DPIA status summary
    public function getDpiaStatus(): array;

    // Get risk heat map data
    public function getRiskHeatMap(): array;

    // Get processing activity summary
    public function getProcessingActivities(): Collection;

    // Get retention compliance status
    public function getRetentionStatus(): array;

    // Get regulatory compliance by regulation
    public function getRegulationCompliance(string $regulation): array;
}
```

#### ComplianceReportGenerator

```php
namespace ArtisanPackUI\Security\Compliance\Reporting;

class ComplianceReportGenerator
{
    // Generate compliance report
    public function generate(string $type, array $options = []): ComplianceReport;

    // Available report types
    public function getReportTypes(): array;

    // Schedule recurring report
    public function schedule(string $type, string $cron, array $recipients): ScheduledComplianceReport;

    // Export report to format
    public function export(ComplianceReport $report, string $format): string;

    // Send report to recipients
    public function send(ComplianceReport $report, array $recipients): void;

    // Get report template
    public function getTemplate(string $type): ReportTemplate;

    // Register custom report type
    public function registerType(string $name, ReportTypeInterface $type): void;
}
```

#### Built-in Report Types

```php
// Regulatory reports
GdprComplianceReport::class           // GDPR compliance summary
CcpaComplianceReport::class           // CCPA compliance summary
LgpdComplianceReport::class           // LGPD compliance summary

// Operational reports
DsrStatusReport::class                // Data subject request status
ConsentAnalyticsReport::class         // Consent metrics and trends
RetentionComplianceReport::class      // Retention policy compliance
DpiaStatusReport::class               // DPIA completion status
RiskAssessmentReport::class           // Risk assessment summary
ProcessingActivityReport::class       // Processing activity inventory
ThirdPartyDataFlowReport::class       // Third-party data sharing

// Executive reports
ExecutiveComplianceReport::class      // High-level compliance summary
BoardComplianceReport::class          // Board-level reporting
AuditorReport::class                  // Auditor-ready compliance report
```

#### ComplianceDashboardController

```php
namespace ArtisanPackUI\Security\Http\Controllers;

class ComplianceDashboardController extends Controller
{
    // Get dashboard summary
    public function summary(): JsonResponse;

    // Get compliance score
    public function score(): JsonResponse;

    // Get DSR metrics
    public function dsrMetrics(Request $request): JsonResponse;

    // Get consent analytics
    public function consentAnalytics(): JsonResponse;

    // Get DPIA status
    public function dpiaStatus(): JsonResponse;

    // Get risk heat map
    public function riskHeatMap(): JsonResponse;

    // Get processing activities
    public function processingActivities(): JsonResponse;

    // Get retention status
    public function retentionStatus(): JsonResponse;

    // Generate report
    public function generateReport(Request $request): JsonResponse;

    // Get regulation compliance
    public function regulationCompliance(string $regulation): JsonResponse;
}
```

#### API Endpoints

```
GET  /api/compliance/dashboard/summary
GET  /api/compliance/dashboard/score
GET  /api/compliance/dashboard/dsr-metrics
GET  /api/compliance/dashboard/consent-analytics
GET  /api/compliance/dashboard/dpia-status
GET  /api/compliance/dashboard/risk-heat-map
GET  /api/compliance/dashboard/processing-activities
GET  /api/compliance/dashboard/retention-status
GET  /api/compliance/dashboard/regulation/{regulation}
POST /api/compliance/reports/generate
GET  /api/compliance/reports/{id}/download
```

#### ComplianceScore Model

```php
namespace ArtisanPackUI\Security\Models;

class ComplianceScore extends Model
{
    protected $fillable = [
        'overall_score',            // 0-100
        'regulation',               // gdpr, ccpa, etc. or 'all'
        'category_scores',          // JSON: scores by category
        'findings',                 // JSON: compliance findings
        'recommendations',          // JSON: improvement recommendations
        'calculated_at',
        'next_calculation_at',
        'calculated_by',            // system or user_id
    ];

    protected $casts = [
        'category_scores' => 'array',
        'findings' => 'array',
        'recommendations' => 'array',
        'calculated_at' => 'datetime',
        'next_calculation_at' => 'datetime',
    ];
}
```

---

## Automated Compliance Checking

### Overview

Automated compliance checking continuously monitors the application for compliance violations and potential issues. It provides proactive alerts and remediation guidance.

### Features

1. **Continuous Monitoring** - Real-time compliance checking
2. **Scheduled Audits** - Periodic comprehensive audits
3. **Rule-Based Checks** - Configurable compliance rules
4. **Violation Alerts** - Immediate notification of issues
5. **Remediation Guidance** - Actionable fix suggestions
6. **Compliance Timeline** - Historical compliance tracking
7. **Integration Checks** - Third-party compliance verification

### Check Categories

| Category | Checks Performed |
|----------|-----------------|
| Consent | Valid consent for processing, expired consents, missing consent |
| Retention | Data past retention, missing retention policies |
| Access Control | Unauthorized access, over-privileged accounts |
| Data Protection | Encryption status, security measures |
| Processing | Lawful basis, purpose limitation |
| Documentation | Missing DPIAs, outdated policies |
| Rights | Overdue DSRs, incomplete requests |
| Transfers | Unauthorized transfers, missing safeguards |

### Implementation

#### ComplianceMonitor Service

```php
namespace ArtisanPackUI\Security\Compliance\Monitoring;

class ComplianceMonitor
{
    // Run all enabled checks
    public function runChecks(): ComplianceCheckResult;

    // Run specific check
    public function runCheck(string $checkName): ComplianceCheckResult;

    // Run checks for specific regulation
    public function runRegulationChecks(string $regulation): ComplianceCheckResult;

    // Schedule check execution
    public function schedule(string $checkName, string $cron): void;

    // Register a custom check
    public function registerCheck(string $name, ComplianceCheckInterface $check): void;

    // Get all registered checks
    public function getChecks(): array;

    // Get check results history
    public function getHistory(?string $checkName = null, int $limit = 100): Collection;

    // Get current violations
    public function getViolations(): Collection;

    // Mark violation as resolved
    public function resolveViolation(ComplianceViolation $violation, ?string $notes = null): void;

    // Get compliance trend data
    public function getTrend(Carbon $from, Carbon $to): array;
}
```

#### ComplianceCheckInterface

```php
namespace ArtisanPackUI\Security\Compliance\Contracts;

interface ComplianceCheckInterface
{
    // Get check name
    public function getName(): string;

    // Get check description
    public function getDescription(): string;

    // Get check category
    public function getCategory(): string;

    // Get applicable regulations
    public function getRegulations(): array;

    // Run the check
    public function run(): CheckResult;

    // Check if check is enabled
    public function isEnabled(): bool;

    // Get recommended schedule
    public function getRecommendedSchedule(): string;

    // Get severity of violations found by this check
    public function getSeverity(): string;

    // Get remediation guidance
    public function getRemediation(): string;
}
```

#### Built-in Compliance Checks

```php
// Consent checks
ConsentValidityCheck::class           // Check consent is valid
ConsentExpirationCheck::class         // Check for expiring consent
ConsentCoverageCheck::class           // Check all processing has consent

// Retention checks
RetentionExpirationCheck::class       // Check for expired data
RetentionPolicyCheck::class           // Check policies exist
RetentionEnforcementCheck::class      // Check retention is enforced

// Access control checks
AccessControlCheck::class             // Check access restrictions
PrivilegeCheck::class                 // Check for over-privileged accounts
AuditTrailCheck::class                // Check audit logging

// Data protection checks
EncryptionCheck::class                // Check encryption at rest/transit
SecurityMeasuresCheck::class          // Check security implementations
DataLeakCheck::class                  // Check for potential data leaks

// Documentation checks
DpiaCompletionCheck::class            // Check DPIAs are complete
PolicyUpdateCheck::class              // Check policies are current
ProcessingRecordCheck::class          // Check processing records exist

// Rights fulfillment checks
DsrTimelinessCheck::class             // Check DSR response times
DsrCompletenessCheck::class           // Check DSR completeness

// Transfer checks
TransferLegalityCheck::class          // Check transfer legal basis
TransferSafeguardsCheck::class        // Check transfer safeguards
```

#### ComplianceViolation Model

```php
namespace ArtisanPackUI\Security\Models;

class ComplianceViolation extends Model
{
    protected $fillable = [
        'violation_number',         // Auto-generated: VIO-2025-000001
        'check_name',
        'category',
        'regulation',               // gdpr, ccpa, etc.
        'article_reference',        // e.g., "GDPR Article 17"
        'severity',                 // info, low, medium, high, critical
        'title',
        'description',
        'affected_records',         // JSON: affected record details
        'affected_count',
        'evidence',                 // JSON: evidence of violation
        'remediation_steps',        // JSON: steps to fix
        'remediation_deadline',
        'status',                   // open, acknowledged, in_progress, resolved, accepted
        'assigned_to',
        'acknowledged_at',
        'acknowledged_by',
        'resolved_at',
        'resolved_by',
        'resolution_notes',
        'accepted_risk',            // If accepted rather than resolved
        'risk_acceptance_by',
        'risk_acceptance_reason',
    ];

    protected $casts = [
        'affected_records' => 'array',
        'evidence' => 'array',
        'remediation_steps' => 'array',
        'remediation_deadline' => 'datetime',
        'acknowledged_at' => 'datetime',
        'resolved_at' => 'datetime',
    ];
}
```

#### ComplianceCheckResult Model

```php
namespace ArtisanPackUI\Security\Models;

class ComplianceCheckResult extends Model
{
    protected $fillable = [
        'check_name',
        'status',                   // passed, failed, warning, error
        'score',                    // 0-100
        'violations_found',
        'warnings_found',
        'items_checked',
        'items_compliant',
        'details',                  // JSON: detailed results
        'execution_time_ms',
        'next_run_at',
        'metadata',                 // JSON: additional context
    ];

    protected $casts = [
        'details' => 'array',
        'metadata' => 'array',
        'next_run_at' => 'datetime',
    ];
}
```

---

## Database Schema

### New Tables

```sql
-- Processing activities registry (ROPA)
CREATE TABLE processing_activities (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    controller_name VARCHAR(255),
    controller_contact VARCHAR(255),
    processor_name VARCHAR(255),
    processor_contact VARCHAR(255),
    dpo_contact VARCHAR(255),
    purposes JSON NOT NULL,
    legal_bases JSON NOT NULL,
    data_categories JSON NOT NULL,
    data_subjects JSON NOT NULL,
    recipients JSON,
    third_countries JSON,
    safeguards JSON,
    retention_policy JSON,
    security_measures JSON,
    automated_decisions JSON,
    dpia_required BOOLEAN DEFAULT FALSE,
    dpia_reference VARCHAR(100),
    status ENUM('active', 'suspended', 'terminated') DEFAULT 'active',
    last_review_at TIMESTAMP NULL,
    next_review_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_status (status),
    INDEX idx_dpia_required (dpia_required)
);

-- Data protection impact assessments
CREATE TABLE data_protection_assessments (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    assessment_number VARCHAR(20) NOT NULL UNIQUE,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    processing_activity_id BIGINT UNSIGNED,
    status ENUM('draft', 'in_review', 'approved', 'rejected', 'revision_required') DEFAULT 'draft',
    version INT UNSIGNED DEFAULT 1,
    parent_assessment_id BIGINT UNSIGNED NULL,
    data_categories JSON,
    data_subjects JSON,
    processing_purposes JSON,
    legal_bases JSON,
    recipients JSON,
    retention_periods JSON,
    transfers JSON,
    security_measures JSON,
    overall_risk_score DECIMAL(5, 2),
    overall_risk_level ENUM('low', 'medium', 'high', 'critical'),
    dpo_opinion TEXT,
    dpo_reviewed_at TIMESTAMP NULL,
    dpo_reviewed_by BIGINT UNSIGNED,
    created_by BIGINT UNSIGNED,
    reviewed_by BIGINT UNSIGNED,
    approved_at TIMESTAMP NULL,
    next_review_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_status (status),
    INDEX idx_processing_activity (processing_activity_id),
    INDEX idx_risk_level (overall_risk_level)
);

-- Assessment risks
CREATE TABLE assessment_risks (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    assessment_id BIGINT UNSIGNED NOT NULL,
    risk_category VARCHAR(50) NOT NULL,
    risk_title VARCHAR(255) NOT NULL,
    risk_description TEXT,
    likelihood ENUM('rare', 'unlikely', 'possible', 'likely', 'almost_certain') NOT NULL,
    impact ENUM('negligible', 'minor', 'moderate', 'major', 'severe') NOT NULL,
    inherent_score DECIMAL(5, 2),
    residual_score DECIMAL(5, 2),
    risk_level ENUM('low', 'medium', 'high', 'critical'),
    risk_owner BIGINT UNSIGNED,
    status ENUM('identified', 'mitigating', 'mitigated', 'accepted') DEFAULT 'identified',
    accepted_by BIGINT UNSIGNED,
    accepted_at TIMESTAMP NULL,
    acceptance_justification TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_assessment (assessment_id),
    INDEX idx_risk_level (risk_level)
);

-- Risk mitigations
CREATE TABLE risk_mitigations (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    risk_id BIGINT UNSIGNED NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    type ENUM('technical', 'organizational', 'contractual') NOT NULL,
    status ENUM('planned', 'in_progress', 'implemented', 'verified') DEFAULT 'planned',
    priority ENUM('low', 'medium', 'high', 'critical') DEFAULT 'medium',
    assigned_to BIGINT UNSIGNED,
    due_date DATE,
    implemented_at TIMESTAMP NULL,
    verified_at TIMESTAMP NULL,
    verified_by BIGINT UNSIGNED,
    effectiveness_rating TINYINT UNSIGNED,
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_risk (risk_id),
    INDEX idx_status (status)
);

-- Consent policies
CREATE TABLE consent_policies (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    purpose VARCHAR(100) NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    legal_text TEXT NOT NULL,
    version VARCHAR(20) NOT NULL,
    previous_version_id BIGINT UNSIGNED NULL,
    data_categories JSON,
    processing_details JSON,
    retention_period VARCHAR(100),
    third_party_sharing JSON,
    rights_description TEXT,
    withdrawal_consequences TEXT,
    is_required BOOLEAN DEFAULT FALSE,
    is_active BOOLEAN DEFAULT TRUE,
    requires_explicit BOOLEAN DEFAULT TRUE,
    minimum_age TINYINT UNSIGNED DEFAULT 16,
    effective_at TIMESTAMP NOT NULL,
    expires_at TIMESTAMP NULL,
    changes_from_previous JSON,
    created_by BIGINT UNSIGNED,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY idx_purpose_version (purpose, version),
    INDEX idx_active_purpose (is_active, purpose)
);

-- Consent records
CREATE TABLE consent_records (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    user_id BIGINT UNSIGNED NOT NULL,
    purpose VARCHAR(100) NOT NULL,
    policy_id BIGINT UNSIGNED NOT NULL,
    policy_version VARCHAR(20) NOT NULL,
    status ENUM('granted', 'withdrawn', 'expired') NOT NULL,
    consent_type ENUM('explicit', 'implied') NOT NULL,
    collection_method VARCHAR(50) NOT NULL,
    collection_context JSON,
    ip_address VARCHAR(45),
    user_agent TEXT,
    proof_reference VARCHAR(255),
    granular_choices JSON,
    expires_at TIMESTAMP NULL,
    withdrawn_at TIMESTAMP NULL,
    withdrawal_reason TEXT,
    metadata JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_user_purpose (user_id, purpose),
    INDEX idx_status (status),
    INDEX idx_expires (expires_at)
);

-- Consent audit log
CREATE TABLE consent_audit_logs (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    consent_record_id BIGINT UNSIGNED,
    user_id BIGINT UNSIGNED NOT NULL,
    action ENUM('granted', 'withdrawn', 'expired', 'policy_updated') NOT NULL,
    purpose VARCHAR(100) NOT NULL,
    old_status VARCHAR(20),
    new_status VARCHAR(20),
    policy_version VARCHAR(20),
    actor_type ENUM('user', 'system', 'admin') NOT NULL,
    actor_id BIGINT UNSIGNED,
    reason TEXT,
    ip_address VARCHAR(45),
    user_agent TEXT,
    metadata JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_user (user_id),
    INDEX idx_consent_record (consent_record_id),
    INDEX idx_created (created_at)
);

-- Erasure requests
CREATE TABLE erasure_requests (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    request_number VARCHAR(20) NOT NULL UNIQUE,
    user_id BIGINT UNSIGNED NOT NULL,
    requester_type ENUM('self', 'guardian', 'authorized_agent') DEFAULT 'self',
    requester_contact VARCHAR(255),
    status ENUM('pending', 'verifying', 'approved', 'processing', 'completed', 'rejected') DEFAULT 'pending',
    scope ENUM('full', 'partial') DEFAULT 'full',
    specific_data JSON,
    reason TEXT,
    identity_verified BOOLEAN DEFAULT FALSE,
    identity_verified_at TIMESTAMP NULL,
    identity_verified_method VARCHAR(50),
    exemptions_found JSON,
    exemption_explanation TEXT,
    handlers_processed JSON,
    handlers_failed JSON,
    third_parties_notified JSON,
    certificate_path VARCHAR(500),
    completed_at TIMESTAMP NULL,
    rejected_at TIMESTAMP NULL,
    rejected_by BIGINT UNSIGNED,
    rejection_reason TEXT,
    deadline_at TIMESTAMP NOT NULL,
    created_by BIGINT UNSIGNED,
    processed_by BIGINT UNSIGNED,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_user (user_id),
    INDEX idx_status (status),
    INDEX idx_deadline (deadline_at)
);

-- Erasure logs
CREATE TABLE erasure_logs (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    request_id BIGINT UNSIGNED NOT NULL,
    handler_name VARCHAR(100) NOT NULL,
    action ENUM('find', 'erase', 'verify', 'rollback') NOT NULL,
    status ENUM('success', 'failed', 'skipped') NOT NULL,
    records_found INT UNSIGNED DEFAULT 0,
    records_erased INT UNSIGNED DEFAULT 0,
    records_retained INT UNSIGNED DEFAULT 0,
    retention_reason TEXT,
    backup_reference VARCHAR(255),
    error_message TEXT,
    metadata JSON,
    started_at TIMESTAMP NOT NULL,
    completed_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_request (request_id)
);

-- Portability requests
CREATE TABLE portability_requests (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    request_number VARCHAR(20) NOT NULL UNIQUE,
    user_id BIGINT UNSIGNED NOT NULL,
    requester_type ENUM('self', 'guardian', 'authorized_agent') DEFAULT 'self',
    status ENUM('pending', 'processing', 'completed', 'failed', 'expired') DEFAULT 'pending',
    format ENUM('json', 'xml', 'csv') DEFAULT 'json',
    categories JSON,
    transfer_type ENUM('download', 'direct_transfer') DEFAULT 'download',
    destination_url VARCHAR(500),
    destination_verified BOOLEAN DEFAULT FALSE,
    file_path VARCHAR(500),
    file_size BIGINT UNSIGNED,
    file_hash VARCHAR(64),
    download_count INT UNSIGNED DEFAULT 0,
    download_limit INT UNSIGNED DEFAULT 5,
    expires_at TIMESTAMP NULL,
    completed_at TIMESTAMP NULL,
    downloaded_at TIMESTAMP NULL,
    deadline_at TIMESTAMP NOT NULL,
    created_by BIGINT UNSIGNED,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_user (user_id),
    INDEX idx_status (status),
    INDEX idx_expires (expires_at)
);

-- Export schemas
CREATE TABLE export_schemas (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(100) NOT NULL,
    category VARCHAR(50) NOT NULL,
    version VARCHAR(20) NOT NULL,
    format ENUM('json', 'xml') NOT NULL,
    schema_definition JSON NOT NULL,
    field_mappings JSON,
    transformations JSON,
    is_default BOOLEAN DEFAULT FALSE,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY idx_category_version_format (category, version, format)
);

-- Retention policies
CREATE TABLE retention_policies (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    model_class VARCHAR(255),
    data_category VARCHAR(50),
    retention_days INT UNSIGNED,
    legal_basis TEXT,
    deletion_strategy ENUM('delete', 'anonymize', 'archive') DEFAULT 'delete',
    archive_location VARCHAR(255),
    conditions JSON,
    exceptions JSON,
    notification_days INT UNSIGNED DEFAULT 30,
    is_active BOOLEAN DEFAULT TRUE,
    created_by BIGINT UNSIGNED,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_model (model_class),
    INDEX idx_active (is_active)
);

-- Collection policies
CREATE TABLE collection_policies (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(100) NOT NULL,
    purpose VARCHAR(100) NOT NULL UNIQUE,
    allowed_fields JSON,
    required_fields JSON,
    conditional_fields JSON,
    prohibited_fields JSON,
    legal_basis TEXT,
    consent_type ENUM('explicit', 'implied', 'not_required') DEFAULT 'explicit',
    minimization_rules JSON,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_purpose (purpose)
);

-- Compliance violations
CREATE TABLE compliance_violations (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    violation_number VARCHAR(20) NOT NULL UNIQUE,
    check_name VARCHAR(100) NOT NULL,
    category VARCHAR(50) NOT NULL,
    regulation VARCHAR(50),
    article_reference VARCHAR(50),
    severity ENUM('info', 'low', 'medium', 'high', 'critical') NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    affected_records JSON,
    affected_count INT UNSIGNED DEFAULT 0,
    evidence JSON,
    remediation_steps JSON,
    remediation_deadline TIMESTAMP NULL,
    status ENUM('open', 'acknowledged', 'in_progress', 'resolved', 'accepted') DEFAULT 'open',
    assigned_to BIGINT UNSIGNED,
    acknowledged_at TIMESTAMP NULL,
    acknowledged_by BIGINT UNSIGNED,
    resolved_at TIMESTAMP NULL,
    resolved_by BIGINT UNSIGNED,
    resolution_notes TEXT,
    accepted_risk BOOLEAN DEFAULT FALSE,
    risk_acceptance_by BIGINT UNSIGNED,
    risk_acceptance_reason TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_status_severity (status, severity),
    INDEX idx_check (check_name),
    INDEX idx_regulation (regulation)
);

-- Compliance check results
CREATE TABLE compliance_check_results (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    check_name VARCHAR(100) NOT NULL,
    status ENUM('passed', 'failed', 'warning', 'error') NOT NULL,
    score DECIMAL(5, 2),
    violations_found INT UNSIGNED DEFAULT 0,
    warnings_found INT UNSIGNED DEFAULT 0,
    items_checked INT UNSIGNED DEFAULT 0,
    items_compliant INT UNSIGNED DEFAULT 0,
    details JSON,
    execution_time_ms INT UNSIGNED,
    next_run_at TIMESTAMP NULL,
    metadata JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_check_name (check_name),
    INDEX idx_status (status),
    INDEX idx_created (created_at)
);

-- Compliance scores
CREATE TABLE compliance_scores (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    overall_score DECIMAL(5, 2) NOT NULL,
    regulation VARCHAR(50) DEFAULT 'all',
    category_scores JSON,
    findings JSON,
    recommendations JSON,
    calculated_at TIMESTAMP NOT NULL,
    next_calculation_at TIMESTAMP NULL,
    calculated_by VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_regulation (regulation),
    INDEX idx_calculated (calculated_at)
);

-- Scheduled compliance reports
CREATE TABLE scheduled_compliance_reports (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    report_type VARCHAR(50) NOT NULL,
    name VARCHAR(100) NOT NULL,
    cron_expression VARCHAR(100) NOT NULL,
    recipients JSON NOT NULL,
    options JSON,
    format ENUM('pdf', 'html', 'csv', 'json') DEFAULT 'pdf',
    is_active BOOLEAN DEFAULT TRUE,
    last_run_at TIMESTAMP NULL,
    next_run_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_active_next (is_active, next_run_at)
);
```

---

## Configuration

### config/security-compliance.php

```php
return [
    'compliance' => [
        'enabled' => env('COMPLIANCE_ENABLED', true),

        // Default regulation to enforce
        'default_regulation' => env('COMPLIANCE_REGULATION', 'gdpr'),

        // Supported regulations
        'regulations' => ['gdpr', 'ccpa', 'lgpd', 'pipeda', 'popia', 'pdpa'],

        // Data Protection Impact Assessments
        'dpia' => [
            'enabled' => true,
            'auto_require_high_risk' => true,
            'review_reminder_days' => 365,
            'require_dpo_review' => true,
            'export_formats' => ['pdf', 'docx', 'html'],
        ],

        // Privacy by Design
        'privacy_by_design' => [
            'enabled' => true,
            'auto_encrypt_sensitive' => true,
            'log_data_access' => true,
            'default_retention_days' => null, // null = indefinite
            'audit_trail_enabled' => true,
        ],

        // Data Minimization
        'minimization' => [
            'enabled' => true,
            'enforce_collection_policies' => true,
            'auto_purge_expired' => env('AUTO_PURGE_EXPIRED_DATA', false),
            'purge_batch_size' => 1000,
            'anonymization_algorithm' => 'sha256', // sha256, bcrypt
        ],

        // Right to Erasure
        'erasure' => [
            'enabled' => true,
            'require_identity_verification' => true,
            'verification_methods' => ['email', 'sms', 'document'],
            'grace_period_days' => 7, // Days before permanent deletion
            'deadline_days' => 30, // Legal deadline to respond
            'notify_third_parties' => true,
            'generate_certificate' => true,
            'handlers' => [
                // List of erasure handler classes
            ],
        ],

        // Data Portability
        'portability' => [
            'enabled' => true,
            'deadline_days' => 30,
            'default_format' => 'json',
            'supported_formats' => ['json', 'xml', 'csv'],
            'download_expiry_hours' => 72,
            'max_download_attempts' => 5,
            'allow_direct_transfer' => true,
            'max_export_size_mb' => 500,
            'chunk_size' => 1000,
        ],

        // Consent Management
        'consent' => [
            'enabled' => true,
            'require_explicit' => true,
            'default_expiry_days' => null, // null = no expiry
            'reconsent_on_policy_change' => true,
            'minimum_age' => 16, // GDPR default
            'cookie_consent' => [
                'enabled' => true,
                'banner_position' => 'bottom',
                'categories' => ['essential', 'functional', 'analytics', 'marketing'],
            ],
            'purposes' => [
                'essential' => [
                    'name' => 'Essential',
                    'required' => true,
                    'description' => 'Required for basic site functionality',
                ],
                'functional' => [
                    'name' => 'Functional',
                    'required' => false,
                    'description' => 'Enhanced functionality and personalization',
                ],
                'analytics' => [
                    'name' => 'Analytics',
                    'required' => false,
                    'description' => 'Usage analytics and improvement',
                ],
                'marketing' => [
                    'name' => 'Marketing',
                    'required' => false,
                    'description' => 'Marketing and advertising',
                ],
            ],
        ],

        // Compliance Dashboard
        'dashboard' => [
            'enabled' => true,
            'refresh_interval' => 300, // seconds
            'require_permission' => 'compliance.dashboard.view',
            'score_calculation_cron' => '0 0 * * *', // Daily at midnight
        ],

        // Automated Compliance Checking
        'monitoring' => [
            'enabled' => true,
            'check_schedule' => '0 */6 * * *', // Every 6 hours
            'checks' => [
                'consent_validity' => ['enabled' => true, 'severity' => 'high'],
                'consent_expiration' => ['enabled' => true, 'severity' => 'medium'],
                'retention_expiration' => ['enabled' => true, 'severity' => 'high'],
                'retention_policy' => ['enabled' => true, 'severity' => 'medium'],
                'dsr_timeliness' => ['enabled' => true, 'severity' => 'critical'],
                'dpia_completion' => ['enabled' => true, 'severity' => 'medium'],
                'encryption' => ['enabled' => true, 'severity' => 'critical'],
                'access_control' => ['enabled' => true, 'severity' => 'high'],
            ],
            'alert_on_violation' => true,
            'alert_channels' => ['email', 'slack'],
            'alert_recipients' => [
                'critical' => ['dpo@example.com'],
                'high' => ['compliance@example.com'],
            ],
        ],

        // Reporting
        'reporting' => [
            'enabled' => true,
            'storage_disk' => 'local',
            'storage_path' => 'compliance-reports',
            'default_format' => 'pdf',
            'include_pii' => false, // Include PII in reports
            'retention_days' => 730, // 2 years
        ],

        // Data Categories (GDPR special categories)
        'special_categories' => [
            'racial_ethnic_origin',
            'political_opinions',
            'religious_beliefs',
            'trade_union_membership',
            'genetic_data',
            'biometric_data',
            'health_data',
            'sex_life_orientation',
        ],

        // Legal Bases (GDPR Article 6)
        'legal_bases' => [
            'consent' => 'Consent (Art. 6(1)(a))',
            'contract' => 'Contract (Art. 6(1)(b))',
            'legal_obligation' => 'Legal Obligation (Art. 6(1)(c))',
            'vital_interests' => 'Vital Interests (Art. 6(1)(d))',
            'public_interest' => 'Public Interest (Art. 6(1)(e))',
            'legitimate_interests' => 'Legitimate Interests (Art. 6(1)(f))',
        ],
    ],
];
```

---

## File Structure

```
src/
├── Compliance/
│   ├── Contracts/
│   │   ├── ComplianceCheckInterface.php
│   │   ├── ErasureHandlerInterface.php
│   │   ├── DataExporterInterface.php
│   │   ├── ReportTypeInterface.php
│   │   └── ConsentStorageInterface.php
│   │
│   ├── Assessment/
│   │   ├── DpiaService.php
│   │   ├── RiskAssessor.php
│   │   ├── RiskScore.php
│   │   └── RiskLevel.php
│   │
│   ├── Consent/
│   │   ├── ConsentManager.php
│   │   ├── ConsentPolicyService.php
│   │   ├── ConsentVerification.php
│   │   └── CookieConsentHandler.php
│   │
│   ├── Erasure/
│   │   ├── ErasureService.php
│   │   ├── ErasureResult.php
│   │   ├── Handlers/
│   │   │   ├── UserDataErasureHandler.php
│   │   │   ├── ProfileDataErasureHandler.php
│   │   │   ├── ConsentDataErasureHandler.php
│   │   │   ├── AuditLogErasureHandler.php
│   │   │   ├── SessionDataErasureHandler.php
│   │   │   ├── TokenDataErasureHandler.php
│   │   │   └── ActivityLogErasureHandler.php
│   │   └── CertificateGenerator.php
│   │
│   ├── Portability/
│   │   ├── PortabilityService.php
│   │   ├── ExportResult.php
│   │   ├── TransferResult.php
│   │   ├── Exporters/
│   │   │   ├── UserDataExporter.php
│   │   │   ├── ProfileDataExporter.php
│   │   │   ├── ConsentHistoryExporter.php
│   │   │   ├── ActivityDataExporter.php
│   │   │   └── PreferencesExporter.php
│   │   ├── Formatters/
│   │   │   ├── JsonFormatter.php
│   │   │   ├── XmlFormatter.php
│   │   │   └── CsvFormatter.php
│   │   └── SchemaValidator.php
│   │
│   ├── Minimization/
│   │   ├── DataMinimizerService.php
│   │   ├── AnonymizationEngine.php
│   │   ├── PseudonymizationEngine.php
│   │   ├── RetentionEnforcer.php
│   │   └── CollectionPolicyEnforcer.php
│   │
│   ├── Monitoring/
│   │   ├── ComplianceMonitor.php
│   │   ├── CheckResult.php
│   │   ├── Checks/
│   │   │   ├── ConsentValidityCheck.php
│   │   │   ├── ConsentExpirationCheck.php
│   │   │   ├── RetentionExpirationCheck.php
│   │   │   ├── RetentionPolicyCheck.php
│   │   │   ├── DsrTimelinessCheck.php
│   │   │   ├── DpiaCompletionCheck.php
│   │   │   ├── EncryptionCheck.php
│   │   │   └── AccessControlCheck.php
│   │   └── ViolationHandler.php
│   │
│   ├── Reporting/
│   │   ├── ComplianceDashboardService.php
│   │   ├── ComplianceReportGenerator.php
│   │   ├── ComplianceScore.php
│   │   ├── Reports/
│   │   │   ├── GdprComplianceReport.php
│   │   │   ├── CcpaComplianceReport.php
│   │   │   ├── DsrStatusReport.php
│   │   │   ├── ConsentAnalyticsReport.php
│   │   │   ├── RetentionComplianceReport.php
│   │   │   ├── DpiaStatusReport.php
│   │   │   └── ExecutiveComplianceReport.php
│   │   └── Templates/
│   │       └── (Report templates)
│   │
│   ├── Middleware/
│   │   ├── PrivacyMiddleware.php
│   │   ├── ConsentCheckMiddleware.php
│   │   └── DataMinimizationMiddleware.php
│   │
│   ├── Traits/
│   │   ├── PrivacyByDesign.php
│   │   ├── HasConsent.php
│   │   └── Auditable.php
│   │
│   ├── Validation/
│   │   ├── DataMinimizationValidator.php
│   │   └── ConsentValidator.php
│   │
│   └── Models/
│       └── PrivacyAwareModel.php
│
├── Http/
│   └── Controllers/
│       ├── ComplianceDashboardController.php
│       ├── ConsentController.php
│       ├── ErasureRequestController.php
│       ├── PortabilityRequestController.php
│       ├── DpiaController.php
│       └── ProcessingActivityController.php
│
├── Models/
│   ├── ProcessingActivity.php
│   ├── DataProtectionAssessment.php
│   ├── AssessmentRisk.php
│   ├── RiskMitigation.php
│   ├── ConsentPolicy.php
│   ├── ConsentRecord.php
│   ├── ConsentAuditLog.php
│   ├── ErasureRequest.php
│   ├── ErasureLog.php
│   ├── PortabilityRequest.php
│   ├── ExportSchema.php
│   ├── RetentionPolicy.php
│   ├── CollectionPolicy.php
│   ├── ComplianceViolation.php
│   ├── ComplianceCheckResult.php
│   ├── ComplianceScore.php
│   └── ScheduledComplianceReport.php
│
├── Events/
│   ├── ConsentGranted.php
│   ├── ConsentWithdrawn.php
│   ├── ErasureRequested.php
│   ├── ErasureCompleted.php
│   ├── PortabilityRequested.php
│   ├── PortabilityCompleted.php
│   ├── ComplianceViolationDetected.php
│   └── DpiaApproved.php
│
├── Listeners/
│   ├── LogConsentChange.php
│   ├── ProcessErasureRequest.php
│   ├── ProcessPortabilityRequest.php
│   ├── AlertOnViolation.php
│   └── NotifyDpoOnHighRisk.php
│
├── Console/
│   └── Commands/
│       ├── ComplianceCheckCommand.php
│       ├── EnforceRetentionCommand.php
│       ├── CalculateComplianceScoreCommand.php
│       ├── GenerateComplianceReportCommand.php
│       ├── ProcessPendingErasuresCommand.php
│       ├── SendConsentRemindersCommand.php
│       └── PruneComplianceDataCommand.php
│
├── Jobs/
│   ├── ProcessErasureRequest.php
│   ├── ProcessPortabilityRequest.php
│   ├── RunComplianceChecks.php
│   ├── EnforceRetentionPolicies.php
│   ├── SendComplianceAlert.php
│   └── GenerateComplianceReport.php
│
└── Notifications/
    ├── ErasureRequestReceived.php
    ├── ErasureCompleted.php
    ├── PortabilityRequestReceived.php
    ├── PortabilityCompleted.php
    ├── ConsentExpiringNotification.php
    ├── ComplianceViolationNotification.php
    └── DpiaReviewRequired.php

database/
└── migrations/
    └── compliance/
        ├── 2025_01_01_100001_create_processing_activities_table.php
        ├── 2025_01_01_100002_create_data_protection_assessments_table.php
        ├── 2025_01_01_100003_create_assessment_risks_table.php
        ├── 2025_01_01_100004_create_risk_mitigations_table.php
        ├── 2025_01_01_100005_create_consent_policies_table.php
        ├── 2025_01_01_100006_create_consent_records_table.php
        ├── 2025_01_01_100007_create_consent_audit_logs_table.php
        ├── 2025_01_01_100008_create_erasure_requests_table.php
        ├── 2025_01_01_100009_create_erasure_logs_table.php
        ├── 2025_01_01_100010_create_portability_requests_table.php
        ├── 2025_01_01_100011_create_export_schemas_table.php
        ├── 2025_01_01_100012_create_retention_policies_table.php
        ├── 2025_01_01_100013_create_collection_policies_table.php
        ├── 2025_01_01_100014_create_compliance_violations_table.php
        ├── 2025_01_01_100015_create_compliance_check_results_table.php
        ├── 2025_01_01_100016_create_compliance_scores_table.php
        └── 2025_01_01_100017_create_scheduled_compliance_reports_table.php

config/
└── security-compliance.php
```

---

## Implementation Order

### Phase 1: Foundation (Core Infrastructure)

1. Create configuration file and service provider integration
2. Create all database migrations
3. Implement base models (ProcessingActivity, ConsentPolicy, etc.)
4. Implement PrivacyByDesign trait
5. Create PrivacyAwareModel base class
6. Set up event/listener structure

### Phase 2: Consent Management

1. Implement ConsentManager service
2. Implement ConsentPolicyService
3. Create ConsentRecord and ConsentPolicy models
4. Implement consent audit logging
5. Create ConsentController API endpoints
6. Implement cookie consent integration
7. Create consent verification middleware
8. Add consent-related events and listeners

### Phase 3: Data Minimization

1. Implement DataMinimizerService
2. Implement AnonymizationEngine
3. Implement PseudonymizationEngine
4. Create RetentionPolicy model and service
5. Create CollectionPolicy model and enforcer
6. Implement DataMinimizationValidator
7. Create retention enforcement command
8. Add data minimization middleware

### Phase 4: Right to Erasure

1. Implement ErasureService
2. Create ErasureHandlerInterface
3. Implement built-in erasure handlers
4. Create ErasureRequest model and controller
5. Implement identity verification flow
6. Implement exemption checking
7. Create certificate generator
8. Add third-party notification support
9. Create erasure processing job

### Phase 5: Data Portability

1. Implement PortabilityService
2. Create DataExporterInterface
3. Implement built-in data exporters
4. Implement format converters (JSON, XML, CSV)
5. Create PortabilityRequest model and controller
6. Implement streaming export for large datasets
7. Add direct transfer capability
8. Create export schema validation

### Phase 6: DPIA Tools

1. Implement DpiaService
2. Implement RiskAssessor
3. Create DataProtectionAssessment model
4. Create AssessmentRisk and RiskMitigation models
5. Implement risk calculation algorithms
6. Create DpiaController API endpoints
7. Add DPO review workflow
8. Implement assessment export (PDF/Word)

### Phase 7: Compliance Monitoring

1. Implement ComplianceMonitor service
2. Create ComplianceCheckInterface
3. Implement built-in compliance checks
4. Create ComplianceViolation model
5. Create ComplianceCheckResult model
6. Implement violation alerting
7. Create compliance check command
8. Add check scheduling

### Phase 8: Reporting Dashboard

1. Implement ComplianceDashboardService
2. Implement ComplianceReportGenerator
3. Create ComplianceScore model and calculation
4. Create ComplianceDashboardController
5. Implement dashboard API endpoints
6. Create built-in report types
7. Add scheduled report functionality
8. Create report export functionality

### Phase 9: Testing & Documentation

1. Write unit tests for all services
2. Write feature tests for API endpoints
3. Write integration tests for workflows
4. Create API documentation
5. Create configuration guide
6. Create DPIA workflow guide
7. Create consent integration guide
8. Create compliance checklist documentation

---

## Dependencies

### Required Packages

- `guzzlehttp/guzzle` - HTTP client (already installed)
- `league/csv` - CSV export for portability

### Optional Packages

- `barryvdh/laravel-dompdf` - PDF report generation
- `phpoffice/phpword` - Word document export for DPIAs
- `spatie/laravel-csp` - Content Security Policy integration
- `spatie/laravel-activitylog` - Enhanced audit logging

---

## Security Considerations

1. **Access Control** - All compliance endpoints require proper authentication and authorization
2. **Data Encryption** - Sensitive compliance data encrypted at rest
3. **Audit Trails** - Complete audit trail for all compliance actions
4. **Identity Verification** - Strict verification for erasure/portability requests
5. **Secure Exports** - Encrypted export files with limited download attempts
6. **Rate Limiting** - Protect APIs from abuse
7. **PII Handling** - Careful handling of PII in reports and logs

---

## Performance Considerations

1. **Batch Processing** - Use batching for large erasure/export operations
2. **Queue Integration** - Queue long-running compliance tasks
3. **Caching** - Cache compliance scores and check results
4. **Streaming** - Stream large data exports
5. **Database Indexing** - Proper indexes on frequently queried columns
6. **Pagination** - Paginate large result sets in APIs
7. **Scheduled Tasks** - Run expensive checks during off-peak hours

---

## API Endpoints Summary

```
# Consent Management
GET    /api/compliance/consent/status
POST   /api/compliance/consent/grant
POST   /api/compliance/consent/withdraw
GET    /api/compliance/consent/history

# Erasure (Right to be Forgotten)
POST   /api/compliance/erasure/request
GET    /api/compliance/erasure/request/{id}
GET    /api/compliance/erasure/requests
POST   /api/compliance/erasure/verify/{id}
GET    /api/compliance/erasure/certificate/{id}

# Portability
POST   /api/compliance/portability/request
GET    /api/compliance/portability/request/{id}
GET    /api/compliance/portability/requests
GET    /api/compliance/portability/download/{id}

# DPIA
GET    /api/compliance/dpia
POST   /api/compliance/dpia
GET    /api/compliance/dpia/{id}
PUT    /api/compliance/dpia/{id}
POST   /api/compliance/dpia/{id}/submit
POST   /api/compliance/dpia/{id}/review
GET    /api/compliance/dpia/{id}/export

# Processing Activities
GET    /api/compliance/processing-activities
POST   /api/compliance/processing-activities
GET    /api/compliance/processing-activities/{id}
PUT    /api/compliance/processing-activities/{id}

# Dashboard & Reporting
GET    /api/compliance/dashboard/summary
GET    /api/compliance/dashboard/score
GET    /api/compliance/dashboard/dsr-metrics
GET    /api/compliance/dashboard/consent-analytics
GET    /api/compliance/dashboard/violations
POST   /api/compliance/reports/generate
GET    /api/compliance/reports/{id}
```
