---
title: Advanced Authentication Guide
---

# Advanced Authentication Guide

This guide covers advanced authentication features including Social Login, Single Sign-On (SSO), WebAuthn/Passkeys, Biometric Authentication, and Device Fingerprinting.

## Social Authentication (OAuth2/OIDC)

Social authentication allows users to log in using their existing accounts from providers like Google, Microsoft, GitHub, Facebook, Apple, and LinkedIn.

### Configuration

Enable and configure social providers in `config/artisanpack/security.php`:

```php
'social_auth' => [
    'enabled' => env('SECURITY_SOCIAL_AUTH_ENABLED', true),
    'allow_registration' => true,  // Allow new user registration via social login
    'allow_linking' => true,       // Allow linking multiple social accounts
    'require_email_verification' => true,
    'auto_link_by_email' => true,  // Auto-link to existing users with same email

    'providers' => [
        'google' => [
            'enabled' => env('SOCIAL_GOOGLE_ENABLED', false),
            'client_id' => env('SOCIAL_GOOGLE_CLIENT_ID'),
            'client_secret' => env('SOCIAL_GOOGLE_CLIENT_SECRET'),
            'scopes' => ['openid', 'email', 'profile'],
        ],
        'microsoft' => [
            'enabled' => env('SOCIAL_MICROSOFT_ENABLED', false),
            'client_id' => env('SOCIAL_MICROSOFT_CLIENT_ID'),
            'client_secret' => env('SOCIAL_MICROSOFT_CLIENT_SECRET'),
            'tenant' => env('SOCIAL_MICROSOFT_TENANT', 'common'),
            'scopes' => ['openid', 'email', 'profile', 'User.Read'],
        ],
        'github' => [
            'enabled' => env('SOCIAL_GITHUB_ENABLED', false),
            'client_id' => env('SOCIAL_GITHUB_CLIENT_ID'),
            'client_secret' => env('SOCIAL_GITHUB_CLIENT_SECRET'),
            'scopes' => ['user:email'],
        ],
        'facebook' => [
            'enabled' => env('SOCIAL_FACEBOOK_ENABLED', false),
            'client_id' => env('SOCIAL_FACEBOOK_CLIENT_ID'),
            'client_secret' => env('SOCIAL_FACEBOOK_CLIENT_SECRET'),
            'scopes' => ['email', 'public_profile'],
        ],
        'apple' => [
            'enabled' => env('SOCIAL_APPLE_ENABLED', false),
            'client_id' => env('SOCIAL_APPLE_CLIENT_ID'),
            'team_id' => env('SOCIAL_APPLE_TEAM_ID'),
            'key_id' => env('SOCIAL_APPLE_KEY_ID'),
            'private_key_path' => env('SOCIAL_APPLE_PRIVATE_KEY_PATH'),
            'scopes' => ['name', 'email'],
        ],
        'linkedin' => [
            'enabled' => env('SOCIAL_LINKEDIN_ENABLED', false),
            'client_id' => env('SOCIAL_LINKEDIN_CLIENT_ID'),
            'client_secret' => env('SOCIAL_LINKEDIN_CLIENT_SECRET'),
            'scopes' => ['openid', 'profile', 'email'],
        ],
    ],
],
```

### Setting Up Google OAuth

1. Go to the [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Navigate to APIs & Services > Credentials
4. Create an OAuth 2.0 Client ID
5. Add authorized redirect URIs: `https://yourapp.com/auth/social/google/callback`
6. Copy the Client ID and Client Secret to your `.env`:

```env
SOCIAL_GOOGLE_ENABLED=true
SOCIAL_GOOGLE_CLIENT_ID=your-client-id
SOCIAL_GOOGLE_CLIENT_SECRET=your-client-secret
```

### Setting Up Microsoft Azure AD

1. Go to the [Azure Portal](https://portal.azure.com/)
2. Navigate to Azure Active Directory > App registrations
3. Register a new application
4. Add a redirect URI: `https://yourapp.com/auth/social/microsoft/callback`
5. Create a client secret under Certificates & secrets
6. Configure your `.env`:

```env
SOCIAL_MICROSOFT_ENABLED=true
SOCIAL_MICROSOFT_CLIENT_ID=your-application-id
SOCIAL_MICROSOFT_CLIENT_SECRET=your-client-secret
SOCIAL_MICROSOFT_TENANT=common
```

### Setting Up GitHub OAuth

1. Go to [GitHub Developer Settings](https://github.com/settings/developers)
2. Create a new OAuth App
3. Set the callback URL: `https://yourapp.com/auth/social/github/callback`
4. Configure your `.env`:

```env
SOCIAL_GITHUB_ENABLED=true
SOCIAL_GITHUB_CLIENT_ID=your-client-id
SOCIAL_GITHUB_CLIENT_SECRET=your-client-secret
```

### User Model Setup

Add the `HasSocialIdentities` trait to your User model:

```php
use ArtisanPackUI\Security\Concerns\HasSocialIdentities;

class User extends Authenticatable
{
    use HasSocialIdentities;
}
```

### Using Social Authentication

The package registers routes automatically. Use these URLs in your login page:

```blade
<a href="{{ route('social.redirect', 'google') }}">Login with Google</a>
<a href="{{ route('social.redirect', 'microsoft') }}">Login with Microsoft</a>
<a href="{{ route('social.redirect', 'github') }}">Login with GitHub</a>
```

### Account Linking

Authenticated users can link additional social accounts:

```php
// In a controller
use ArtisanPackUI\Security\Authentication\Social\SocialAuthManager;

public function linkAccount(SocialAuthManager $social, string $provider)
{
    return $social->redirect($provider, linkMode: true);
}

// The callback will automatically link the account to the current user
```

### Managing Linked Accounts

```php
// Get all linked social accounts
$accounts = $user->socialIdentities;

// Check if a specific provider is linked
$hasGoogle = $user->hasSocialIdentity('google');

// Unlink an account
$user->unlinkSocialIdentity('google');
```

### Livewire Component

Use the built-in Livewire component for managing social accounts:

```blade
<livewire:social-accounts-manager />
```

### Events

The package fires these events for social authentication:

- `SocialLoginSucceeded` - User successfully logged in via social provider
- `SocialAccountLinked` - Social account linked to existing user
- `SocialAccountUnlinked` - Social account unlinked from user

```php
use ArtisanPackUI\Security\Events\SocialLoginSucceeded;

Event::listen(SocialLoginSucceeded::class, function ($event) {
    Log::info('Social login', [
        'user_id' => $event->user->id,
        'provider' => $event->provider,
    ]);
});
```

---

## Single Sign-On (SSO)

Enterprise SSO enables authentication through SAML 2.0, OpenID Connect (OIDC), or LDAP/Active Directory.

### Configuration

```php
'sso' => [
    'enabled' => env('SECURITY_SSO_ENABLED', true),
    'jit_provisioning' => true,  // Just-In-Time user creation
    'default_role' => 'user',    // Default role for JIT users

    'saml' => [
        'entity_id' => env('SAML_ENTITY_ID'),
        'acs_url' => env('SAML_ACS_URL'),
        'sls_url' => env('SAML_SLS_URL'),
        'want_assertions_signed' => true,
        'want_messages_signed' => true,
        'sp_certificate' => env('SAML_SP_CERTIFICATE_PATH'),
        'sp_private_key' => env('SAML_SP_PRIVATE_KEY_PATH'),
    ],

    'oidc' => [
        'response_type' => 'code',
        'scopes' => ['openid', 'email', 'profile'],
    ],

    'ldap' => [
        'port' => 389,
        'use_ssl' => false,
        'use_tls' => true,
        'timeout' => 5,
    ],
],
```

### Creating SSO Configurations

SSO configurations are stored in the database for dynamic management:

```php
use ArtisanPackUI\Security\Models\SsoConfiguration;

// Create a SAML configuration
$samlConfig = SsoConfiguration::create([
    'name' => 'Corporate SSO',
    'type' => 'saml',
    'identifier' => 'corporate',
    'is_active' => true,
    'settings' => [
        'idp_entity_id' => 'https://idp.corporate.com/saml',
        'idp_sso_url' => 'https://idp.corporate.com/saml/sso',
        'idp_slo_url' => 'https://idp.corporate.com/saml/slo',
        'idp_certificate' => '-----BEGIN CERTIFICATE-----...',
    ],
    'attribute_mapping' => [
        'email' => 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress',
        'name' => 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name',
        'groups' => 'http://schemas.microsoft.com/ws/2008/06/identity/claims/groups',
    ],
]);

// Create an OIDC configuration
$oidcConfig = SsoConfiguration::create([
    'name' => 'Okta SSO',
    'type' => 'oidc',
    'identifier' => 'okta',
    'is_active' => true,
    'settings' => [
        'issuer' => 'https://yourorg.okta.com',
        'client_id' => 'your-client-id',
        'client_secret' => 'your-client-secret',
        'authorization_endpoint' => 'https://yourorg.okta.com/oauth2/v1/authorize',
        'token_endpoint' => 'https://yourorg.okta.com/oauth2/v1/token',
        'userinfo_endpoint' => 'https://yourorg.okta.com/oauth2/v1/userinfo',
    ],
]);

// Create an LDAP configuration
$ldapConfig = SsoConfiguration::create([
    'name' => 'Active Directory',
    'type' => 'ldap',
    'identifier' => 'ad',
    'is_active' => true,
    'settings' => [
        'hosts' => ['ldap.corporate.com'],
        'base_dn' => 'dc=corporate,dc=com',
        'username' => 'cn=service,ou=users,dc=corporate,dc=com',
        'password' => 'service-password',
        'user_dn_format' => 'cn=%s,ou=users,dc=corporate,dc=com',
        'user_filter' => '(&(objectClass=person)(sAMAccountName=%s))',
    ],
]);
```

### User Model Setup

Add the `HasSsoIdentities` trait:

```php
use ArtisanPackUI\Security\Concerns\HasSsoIdentities;

class User extends Authenticatable
{
    use HasSsoIdentities;
}
```

### SSO Login URLs

```blade
@foreach(\ArtisanPackUI\Security\Models\SsoConfiguration::active()->get() as $sso)
    <a href="{{ route('sso.login', $sso->identifier) }}">
        Login with {{ $sso->name }}
    </a>
@endforeach
```

### Just-In-Time Provisioning

When JIT provisioning is enabled, users are automatically created on first SSO login:

```php
// Customize JIT user creation
use ArtisanPackUI\Security\Events\SsoLoginSucceeded;

Event::listen(SsoLoginSucceeded::class, function ($event) {
    if ($event->wasProvisioned) {
        // User was just created
        $event->user->assignRole('employee');

        // Sync groups from SSO attributes
        if (isset($event->attributes['groups'])) {
            $event->user->syncRolesFromSsoGroups($event->attributes['groups']);
        }
    }
});
```

### Managing SSO via Artisan

```bash
# List SSO configurations
php artisan sso:manage --list

# Enable/disable a configuration
php artisan sso:manage corporate --enable
php artisan sso:manage corporate --disable

# Test SSO configuration
php artisan sso:manage corporate --test
```

---

## WebAuthn / Passkeys

WebAuthn enables passwordless authentication using security keys (YubiKey), platform authenticators (Touch ID, Face ID, Windows Hello), and passkeys.

### Configuration

```php
'webauthn' => [
    'enabled' => env('SECURITY_WEBAUTHN_ENABLED', true),

    'relying_party' => [
        'name' => env('WEBAUTHN_RP_NAME'),  // Your app name
        'id' => env('WEBAUTHN_RP_ID'),      // Your domain (e.g., 'example.com')
    ],

    'authenticator_selection' => [
        'authenticator_attachment' => null,  // 'platform', 'cross-platform', or null
        'resident_key' => 'preferred',       // 'required' for passkeys
        'user_verification' => 'preferred',
    ],

    'attestation' => 'none',
    'timeout' => 60000,  // 60 seconds
    'allow_multiple_credentials' => true,
    'max_credentials_per_user' => 10,
],
```

### User Model Setup

```php
use ArtisanPackUI\Security\Concerns\HasWebAuthnCredentials;

class User extends Authenticatable
{
    use HasWebAuthnCredentials;
}
```

### Registration Ceremony

```php
use ArtisanPackUI\Security\Authentication\WebAuthn\WebAuthnManager;

class WebAuthnController extends Controller
{
    public function __construct(private WebAuthnManager $webauthn) {}

    // Step 1: Get registration options
    public function registerOptions(Request $request)
    {
        $options = $this->webauthn->generateRegistrationOptions(
            $request->user()
        );

        // Store challenge in session
        session(['webauthn_challenge' => $options['challenge']]);

        return response()->json($options);
    }

    // Step 2: Verify and store credential
    public function register(Request $request)
    {
        $credential = $this->webauthn->verifyRegistration(
            $request->user(),
            $request->all(),
            session('webauthn_challenge')
        );

        session()->forget('webauthn_challenge');

        return response()->json([
            'success' => true,
            'credential_id' => $credential->id,
        ]);
    }
}
```

### Authentication Ceremony

```php
// Step 1: Get authentication options
public function loginOptions(Request $request)
{
    $options = $this->webauthn->generateAuthenticationOptions(
        $request->input('email')  // Optional: for user-specific credentials
    );

    session(['webauthn_challenge' => $options['challenge']]);

    return response()->json($options);
}

// Step 2: Verify assertion
public function login(Request $request)
{
    $user = $this->webauthn->verifyAuthentication(
        $request->all(),
        session('webauthn_challenge')
    );

    if ($user) {
        Auth::login($user);
        session()->forget('webauthn_challenge');
        return redirect('/dashboard');
    }

    return back()->withErrors(['webauthn' => 'Authentication failed']);
}
```

### JavaScript Integration

```javascript
// Registration
async function registerWebAuthn() {
    // Get options from server
    const optionsResponse = await fetch('/webauthn/register/options', {
        method: 'POST',
        headers: { 'X-CSRF-TOKEN': csrfToken }
    });
    const options = await optionsResponse.json();

    // Create credential
    const credential = await navigator.credentials.create({
        publicKey: {
            ...options,
            challenge: base64ToBuffer(options.challenge),
            user: {
                ...options.user,
                id: base64ToBuffer(options.user.id)
            }
        }
    });

    // Send to server
    await fetch('/webauthn/register', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRF-TOKEN': csrfToken
        },
        body: JSON.stringify({
            id: credential.id,
            rawId: bufferToBase64(credential.rawId),
            response: {
                clientDataJSON: bufferToBase64(credential.response.clientDataJSON),
                attestationObject: bufferToBase64(credential.response.attestationObject)
            },
            type: credential.type
        })
    });
}
```

### Livewire Component

```blade
<livewire:web-authn-credentials-manager />
```

### Managing Credentials

```php
// List user's credentials
$credentials = $user->webAuthnCredentials;

// Revoke a credential
$user->revokeWebAuthnCredential($credentialId);

// Check if user has WebAuthn enabled
if ($user->hasWebAuthnCredentials()) {
    // Offer WebAuthn login option
}
```

---

## Biometric Authentication

Biometric authentication uses platform authenticators for Touch ID, Face ID, and Windows Hello.

### Configuration

```php
'biometric' => [
    'enabled' => env('SECURITY_BIOMETRIC_ENABLED', true),

    'providers' => [
        'webauthn' => [
            'enabled' => true,
            'driver' => \ArtisanPackUI\Security\Authentication\Biometric\WebAuthnBiometricProvider::class,
        ],
    ],

    'default' => 'webauthn',
    'allow_primary_auth' => true,
    'require_for_sensitive_actions' => true,
],
```

### Using Biometric Authentication

```php
use ArtisanPackUI\Security\Authentication\Biometric\BiometricManager;

class BiometricController extends Controller
{
    public function __construct(private BiometricManager $biometric) {}

    public function enroll(Request $request)
    {
        $options = $this->biometric->generateEnrollmentOptions(
            $request->user(),
            'platform'  // Force platform authenticator
        );

        return response()->json($options);
    }

    public function verify(Request $request)
    {
        $verified = $this->biometric->verify(
            $request->user(),
            $request->all()
        );

        if ($verified) {
            // Mark session as biometrically verified
            session(['biometric_verified_at' => now()]);
        }

        return response()->json(['verified' => $verified]);
    }
}
```

### Livewire Component

```blade
<livewire:biometric-manager />
```

---

## Device Fingerprinting

Device fingerprinting helps detect new devices and suspicious login attempts.

### Configuration

```php
'device_fingerprinting' => [
    'enabled' => env('SECURITY_DEVICE_FINGERPRINTING_ENABLED', true),

    'components' => [
        'user_agent' => true,
        'accept_language' => true,
        'timezone' => true,
        'screen_resolution' => true,
        'canvas' => true,
        'webgl' => true,
    ],

    'trust_thresholds' => [
        'suspicious' => 30,
        'trusted' => 70,
    ],

    'auto_trust_after_logins' => 3,
    'max_devices_per_user' => 10,
    'notify_on_new_device' => true,
],
```

### User Model Setup

```php
use ArtisanPackUI\Security\Concerns\HasDevices;

class User extends Authenticatable
{
    use HasDevices;
}
```

### Collecting Device Fingerprint

Include the fingerprinting script on your login page:

```blade
<script src="{{ asset('vendor/security/fingerprint.js') }}"></script>
<script>
    document.addEventListener('DOMContentLoaded', async () => {
        const fingerprint = await SecurityFingerprint.collect();
        document.getElementById('device_fingerprint').value = JSON.stringify(fingerprint);
    });
</script>

<form method="POST" action="/login">
    @csrf
    <input type="hidden" name="device_fingerprint" id="device_fingerprint">
    <!-- Other login fields -->
</form>
```

### Processing Device Fingerprint

```php
use ArtisanPackUI\Security\Authentication\Device\DeviceFingerprintService;

class LoginController extends Controller
{
    public function login(Request $request, DeviceFingerprintService $deviceService)
    {
        // Authenticate user...

        // Process device fingerprint
        $fingerprint = json_decode($request->input('device_fingerprint'), true);
        $device = $deviceService->processFingerprint(
            $request->user(),
            $fingerprint,
            $request->ip()
        );

        if ($device->isNew()) {
            // New device detected - notification sent automatically
        }

        if ($device->trust_score < 30) {
            // Suspicious device - require additional verification
            return redirect()->route('verify.device');
        }
    }
}
```

### Managing Devices

```php
// Get user's devices
$devices = $user->devices;

// Get trusted devices
$trustedDevices = $user->trustedDevices();

// Trust a device
$device->markAsTrusted();

// Revoke a device
$user->revokeDevice($deviceId);
```

### Livewire Component

```blade
<livewire:device-manager />
```

---

## Events and Notifications

All advanced authentication features emit events and can send notifications:

### Events

| Event | Trigger |
|-------|---------|
| `SocialLoginSucceeded` | Successful social login |
| `SocialAccountLinked` | Account linked |
| `SocialAccountUnlinked` | Account unlinked |
| `SsoLoginSucceeded` | Successful SSO login |
| `WebAuthnAuthenticated` | WebAuthn login |
| `BiometricAuthenticated` | Biometric verification |
| `BiometricRegistered` | Biometric enrolled |
| `NewDeviceDetected` | New device login |
| `DeviceTrusted` | Device marked trusted |
| `DeviceRevoked` | Device revoked |

### Notification Configuration

```php
'notifications' => [
    'enabled' => true,
    'new_device_login' => true,
    'webauthn_credential' => true,
    'social_account' => true,
],
```

## Related Documentation

- [Session Security Guide](session-security.md)
- [Two-Factor Authentication](two-factor-authentication.md)
- [Troubleshooting Guide](troubleshooting.md)
