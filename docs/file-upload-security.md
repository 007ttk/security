---
title: File Upload Security Guide
---

# File Upload Security Guide

This guide covers secure file upload handling including validation, malware scanning, rate limiting, and secure storage.

## Overview

File uploads are a common attack vector. The ArtisanPack Security package provides:

- **File Type Validation**: MIME type and extension allowlists
- **Content Validation**: Deep inspection of file contents
- **Malware Scanning**: Integration with ClamAV and VirusTotal
- **Rate Limiting**: Prevent abuse through upload limits
- **Secure Storage**: Encrypted storage with signed URLs
- **Quarantine System**: Isolate suspicious files for review

## Configuration

Configure file upload security in `config/artisanpack/security.php`:

```php
'fileUpload' => [
    'enabled' => env('SECURITY_FILE_UPLOAD_ENABLED', true),

    // Allowed file types (allowlist)
    'allowedMimeTypes' => [
        'image/jpeg',
        'image/png',
        'image/gif',
        'image/webp',
        'application/pdf',
        'text/plain',
        'text/csv',
    ],

    'allowedExtensions' => [
        'jpg', 'jpeg', 'png', 'gif', 'webp',
        'pdf', 'txt', 'csv',
    ],

    // Always blocked (blocklist)
    'blockedExtensions' => [
        'php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'phps',
        'exe', 'com', 'bat', 'cmd', 'sh', 'bash',
        'js', 'jsx', 'ts', 'tsx',
        'asp', 'aspx', 'jsp', 'cgi', 'pl', 'py', 'rb',
        'htaccess', 'htpasswd',
        'svg',  // Can contain embedded scripts
    ],

    'blockedMimeTypes' => [
        'application/x-httpd-php',
        'application/x-php',
        'application/x-executable',
        'application/javascript',
        'image/svg+xml',
    ],

    // Size restrictions
    'maxFileSize' => 10 * 1024 * 1024,  // 10 MB
    'maxFileSizePerType' => [
        'image/*' => 5 * 1024 * 1024,           // 5 MB
        'application/pdf' => 20 * 1024 * 1024,  // 20 MB
    ],

    // Content validation
    'validateMimeByContent' => true,
    'checkForDoubleExtensions' => true,
    'checkForNullBytes' => true,
    'stripExifData' => true,

    // Malware scanning
    'malwareScanning' => [
        'enabled' => env('SECURITY_MALWARE_SCANNING_ENABLED', false),
        'driver' => env('SECURITY_MALWARE_DRIVER', 'null'),
        'failOnScanError' => true,
        'async' => false,
        'quarantinePath' => storage_path('app/quarantine'),
    ],

    // Rate limiting
    'rateLimiting' => [
        'enabled' => true,
        'maxUploadsPerMinute' => 10,
        'maxUploadsPerHour' => 100,
        'maxTotalSizePerHour' => 100 * 1024 * 1024,
    ],

    // Secure storage
    'storage' => [
        'disk' => 'local',
        'path' => 'secure-uploads',
        'hashFilenames' => true,
        'preserveOriginalName' => true,
        'organizeByDate' => true,
    ],

    // Secure serving
    'serving' => [
        'useSignedUrls' => true,
        'signedUrlExpiration' => 60,
        'forceDownload' => false,
    ],
],
```

## Basic Usage

### Validation Rules

Use the built-in validation rule:

```php
use ArtisanPackUI\Security\Rules\SecureFile;

$request->validate([
    'document' => [
        'required',
        'file',
        new SecureFile(),
    ],
]);
```

With custom options:

```php
$request->validate([
    'image' => [
        'required',
        'file',
        (new SecureFile())
            ->allowMimeTypes(['image/jpeg', 'image/png'])
            ->maxSize(5 * 1024 * 1024)  // 5 MB
            ->scanForMalware(),
    ],
]);
```

### Middleware

Apply upload validation and scanning via middleware:

```php
Route::post('/upload', [UploadController::class, 'store'])
    ->middleware(['auth', 'upload.validate', 'upload.scan']);
```

### Secure File Storage

```php
use ArtisanPackUI\Security\Contracts\SecureFileStorageInterface;

class UploadController extends Controller
{
    public function store(
        Request $request,
        SecureFileStorageInterface $storage
    ) {
        $request->validate([
            'file' => ['required', 'file', new SecureFile()],
        ]);

        // Store the file securely
        $secureFile = $storage->store(
            $request->file('file'),
            $request->user(),
            [
                'category' => 'documents',
                'description' => $request->input('description'),
            ]
        );

        return response()->json([
            'id' => $secureFile->id,
            'name' => $secureFile->original_name,
            'size' => $secureFile->size,
            'url' => $secureFile->getSignedUrl(),
        ]);
    }
}
```

## File Type Validation

### MIME Type Validation

The package validates MIME types in two ways:

1. **Extension-based**: Check file extension against allowlist
2. **Content-based**: Inspect actual file content (magic bytes)

```php
'validateMimeByContent' => true,  // Enable deep inspection
```

This prevents attacks where malicious files are renamed (e.g., `malware.php` to `malware.jpg`).

### Double Extension Detection

Detect files like `document.pdf.php`:

```php
'checkForDoubleExtensions' => true,
```

### Null Byte Detection

Detect null byte injection like `file.php%00.jpg`:

```php
'checkForNullBytes' => true,
```

### Custom Validation

Create custom file validators:

```php
use ArtisanPackUI\Security\Contracts\FileValidatorInterface;
use Illuminate\Http\UploadedFile;

class CustomFileValidator implements FileValidatorInterface
{
    public function validate(UploadedFile $file): bool
    {
        // Custom validation logic
        return true;
    }

    public function getErrorMessage(): string
    {
        return 'Custom validation failed.';
    }
}

// Register in a service provider
$this->app->bind(FileValidatorInterface::class, CustomFileValidator::class);
```

## Malware Scanning

### ClamAV Integration

1. Install ClamAV on your server:

```bash
# Ubuntu/Debian
sudo apt-get install clamav clamav-daemon

# Start the daemon
sudo systemctl start clamav-daemon
```

2. Configure the driver:

```php
'malwareScanning' => [
    'enabled' => true,
    'driver' => 'clamav',

    'clamav' => [
        'socketPath' => '/var/run/clamav/clamd.sock',
        'binaryPath' => '/usr/bin/clamscan',
        'timeout' => 30,
    ],
],
```

### VirusTotal Integration

For cloud-based scanning:

```php
'malwareScanning' => [
    'enabled' => true,
    'driver' => 'virustotal',

    'virustotal' => [
        'apiKey' => env('VIRUSTOTAL_API_KEY'),
        'timeout' => 60,
    ],
],
```

Note: VirusTotal has API rate limits. Consider using for high-risk file types only.

### Async Scanning

For large files, use async scanning with quarantine:

```php
'malwareScanning' => [
    'enabled' => true,
    'async' => true,
    'quarantinePath' => storage_path('app/quarantine'),
],
```

Files are quarantined until scan completes. A job processes the queue:

```bash
php artisan security:scan-quarantine
```

### Custom Scanner

Implement your own scanner:

```php
use ArtisanPackUI\Security\Contracts\MalwareScannerInterface;
use ArtisanPackUI\Security\Scanning\ScanResult;

class CustomScanner implements MalwareScannerInterface
{
    public function scan(string $filePath): ScanResult
    {
        // Your scanning logic
        $isClean = $this->performScan($filePath);

        if ($isClean) {
            return ScanResult::clean($this->getName());
        }

        return ScanResult::infected('Malware.Generic', $this->getName());
    }

    public function getName(): string
    {
        return 'custom-scanner';
    }

    public function isAvailable(): bool
    {
        return true;
    }

    private function performScan(string $filePath): bool
    {
        // Your custom scanning implementation
        return true;
    }
}
```

## Rate Limiting

### Configuration

```php
'rateLimiting' => [
    'enabled' => true,
    'maxUploadsPerMinute' => 10,
    'maxUploadsPerHour' => 100,
    'maxTotalSizePerHour' => 100 * 1024 * 1024,  // 100 MB
],
```

### Custom Rate Limiting

```php
use ArtisanPackUI\Security\Services\FileUploadRateLimiter;

class UploadController extends Controller
{
    public function store(
        Request $request,
        FileUploadRateLimiter $rateLimiter
    ) {
        // Check rate limit before processing
        if (!$rateLimiter->attempt($request->user())) {
            return response()->json([
                'error' => 'Too many uploads. Please try again later.',
            ], 429);
        }

        // Process upload...
    }
}
```

### Per-User Limits

```php
// In a custom rate limiter
public function getLimit(User $user): int
{
    if ($user->hasRole('premium')) {
        return 1000;  // Premium users get more uploads
    }

    return 100;
}
```

## Secure Storage

### Hash-Based Filenames

Store files with hashed names to prevent enumeration:

```php
'storage' => [
    'hashFilenames' => true,
    'preserveOriginalName' => true,  // Store original in metadata
],
```

Result: `a1b2c3d4e5f6.pdf` instead of `confidential-report.pdf`

### Date-Organized Directories

```php
'storage' => [
    'organizeByDate' => true,
],
```

Result: `secure-uploads/2024/01/15/a1b2c3d4e5f6.pdf`

### Encrypted Storage

Files can be encrypted at rest:

```php
use ArtisanPackUI\Security\Contracts\SecureFileStorageInterface;

$storage->store($file, $user, [
    'encrypt' => true,
]);
```

### User Model Association

Add the trait to associate files with users:

```php
use ArtisanPackUI\Security\Concerns\HasSecureFiles;

class User extends Authenticatable
{
    use HasSecureFiles;
}

// Usage
$user->secureFiles;
$user->secureFiles()->where('category', 'documents')->get();
```

## Secure File Serving

### Signed URLs

Generate time-limited URLs for file access:

```php
$file = SecureUploadedFile::find($id);

// Default expiration (from config)
$url = $file->getSignedUrl();

// Custom expiration (30 minutes)
$url = $file->getSignedUrl(30);
```

### Force Download

Prevent files from being displayed inline:

```php
'serving' => [
    'forceDownload' => true,
],
```

### Access Control

The file controller checks authorization:

```php
use ArtisanPackUI\Security\Http\Controllers\SecureFileController;

// In your routes
Route::get('/files/{file}', [SecureFileController::class, 'show'])
    ->middleware('auth')
    ->name('secure-file.show');
```

Custom authorization:

```php
// In AuthServiceProvider
Gate::define('download-file', function (User $user, SecureUploadedFile $file) {
    return $user->id === $file->user_id
        || $user->hasRole('admin');
});
```

## Quarantine System

### Managing Quarantined Files

```bash
# Scan quarantined files (default limit: 100)
php artisan security:scan-quarantine

# Scan with custom limit
php artisan security:scan-quarantine --limit=50

# Scan and automatically delete infected files
php artisan security:scan-quarantine --delete-infected
```

### Quarantine Events

```php
use ArtisanPackUI\Security\Events\MalwareDetected;

Event::listen(MalwareDetected::class, function ($event) {
    Log::critical('Malware detected', [
        'file' => $event->filename,
        'user_id' => $event->userId,
        'threats' => $event->threats,
    ]);

    // Notify security team
    Notification::route('slack', config('services.slack.security'))
        ->notify(new MalwareDetectedNotification($event));
});
```

## EXIF Data Stripping

Remove potentially sensitive metadata from images:

```php
'stripExifData' => true,
```

This removes:
- GPS coordinates
- Camera information
- Timestamps
- Software used
- Author information

## Events

The file upload system emits these events:

| Event | Trigger |
|-------|---------|
| `FileUploaded` | File successfully uploaded |
| `FileUploadRejected` | Upload rejected (validation/size/type) |
| `MalwareDetected` | Malware found in file |
| `FileServed` | File downloaded |
| `FileDeleted` | File deleted |

## Commands

```bash
# Clean up expired/temporary files
php artisan security:cleanup-files

# Clean files older than 30 days
php artisan security:cleanup-files --days=30

# Clean only infected files
php artisan security:cleanup-files --only-infected

# Preview cleanup without deleting
php artisan security:cleanup-files --dry-run

# Scan quarantined files
php artisan security:scan-quarantine

# Scan with limit and auto-delete infected
php artisan security:scan-quarantine --limit=100 --delete-infected
```

## Best Practices

### 1. Never Trust File Extensions

Always validate by content:

```php
'validateMimeByContent' => true,
```

### 2. Store Outside Web Root

```php
'storage' => [
    'disk' => 'local',  // Not 'public'
    'path' => 'secure-uploads',
],
```

### 3. Use Signed URLs

```php
'serving' => [
    'useSignedUrls' => true,
    'signedUrlExpiration' => 60,
],
```

### 4. Enable Rate Limiting

```php
'rateLimiting' => [
    'enabled' => true,
    'maxUploadsPerMinute' => 10,
],
```

### 5. Scan High-Risk Files

At minimum, scan these file types:
- Office documents (docx, xlsx, pptx)
- PDFs
- Archives (zip, rar)
- Executables (if allowed)

### 6. Log All Uploads

```php
'logging' => [
    'uploads' => true,
    'rejections' => true,
    'malwareDetections' => true,
],
```

## Image Processing Security

When processing uploaded images:

```php
use Intervention\Image\Facades\Image;

// Reprocess image to remove any embedded code
$image = Image::make($uploadedFile);
$image->encode('jpg', 80);  // Re-encode as JPEG
$image->save($path);
```

## Example: Complete Upload Controller

```php
<?php

namespace App\Http\Controllers;

use ArtisanPackUI\Security\Contracts\SecureFileStorageInterface;
use ArtisanPackUI\Security\Rules\SecureFile;
use ArtisanPackUI\Security\Services\FileUploadRateLimiter;
use Illuminate\Http\Request;

class DocumentController extends Controller
{
    public function __construct(
        private SecureFileStorageInterface $storage,
        private FileUploadRateLimiter $rateLimiter
    ) {}

    public function store(Request $request)
    {
        // Check rate limit
        if (!$this->rateLimiter->attempt($request->user())) {
            return response()->json([
                'error' => 'Upload limit exceeded. Try again later.',
            ], 429);
        }

        // Validate
        $request->validate([
            'document' => [
                'required',
                'file',
                (new SecureFile())
                    ->allowMimeTypes(['application/pdf'])
                    ->maxSize(20 * 1024 * 1024)
                    ->scanForMalware(),
            ],
            'title' => 'required|string|max:255',
        ]);

        // Store securely
        $file = $this->storage->store(
            $request->file('document'),
            $request->user(),
            [
                'category' => 'documents',
                'title' => $request->input('title'),
            ]
        );

        return response()->json([
            'id' => $file->id,
            'title' => $file->metadata['title'],
            'url' => $file->getSignedUrl(),
        ]);
    }

    public function show(string $id)
    {
        $file = $this->storage->find($id);

        $this->authorize('download-file', $file);

        return $this->storage->serve($file);
    }

    public function destroy(string $id)
    {
        $file = $this->storage->find($id);

        $this->authorize('delete-file', $file);

        $this->storage->delete($file);

        return response()->json(['deleted' => true]);
    }
}
```

## Related Documentation

- [Implementation Guide](implementation-guide.md)
- [Configuration Reference](configuration-reference.md)
- [Troubleshooting Guide](troubleshooting.md)
