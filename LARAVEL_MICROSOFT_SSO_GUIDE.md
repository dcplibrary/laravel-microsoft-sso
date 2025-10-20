# Laravel Microsoft SSO Integration Guide

A comprehensive guide for integrating the `laravel-microsoft-sso` package with the `microsoft-login-service` for centralized Microsoft authentication.

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Microsoft Login Service Setup](#microsoft-login-service-setup)
- [Client Application Setup](#client-application-setup)
- [Configuration](#configuration)
- [API Reference](#api-reference)
- [Testing](#testing)
- [Troubleshooting](#troubleshooting)
- [Production Deployment](#production-deployment)
- [Advanced Usage](#advanced-usage)

## Overview

This integration provides centralized Microsoft OAuth authentication using:

- **Microsoft Login Service**: Dockerized service that handles Microsoft OAuth flow and JWT token generation
- **Laravel Microsoft SSO Package**: Client-side package that validates JWT tokens and manages user sessions
- **Microsoft Entra ID**: Identity provider for authentication

### Benefits

- ✅ **Centralized Authentication**: Single login service for multiple applications
- ✅ **Stateless**: JWT-based authentication without shared sessions
- ✅ **Scalable**: Docker-based deployment with persistent key storage
- ✅ **Secure**: RSA-256 signed JWTs with proper validation
- ✅ **Framework Agnostic**: Service can be used by non-Laravel applications

## Architecture

```
┌─────────────────┐    ┌──────────────────────┐    ┌─────────────────┐
│   Client App    │    │ Microsoft Login      │    │ Microsoft       │
│  (Laravel +     │◄──►│ Service              │◄──►│ Entra ID        │
│   SSO Package)  │    │ (Docker Container)   │    │ (OAuth Provider)│
└─────────────────┘    └──────────────────────┘    └─────────────────┘
         │                        │
         │                        │
         ▼                        ▼
┌─────────────────┐    ┌──────────────────────┐
│   Dashboard     │    │ JWKS Endpoint        │
│  (Protected)    │    │ (/.well-known/       │
└─────────────────┘    │  jwks.json)          │
                       └──────────────────────┘
```

### Authentication Flow

1. **User Access**: User tries to access protected route in client app
2. **Redirect to Login**: App redirects to Microsoft Login Service
3. **Microsoft OAuth**: Service redirects to Microsoft Entra ID for authentication
4. **Token Generation**: Service generates JWT token with user information
5. **Token Validation**: Client app validates JWT using JWKS endpoint
6. **User Session**: Client app creates local user session
7. **Access Granted**: User can access protected resources

## Prerequisites

### System Requirements

- Docker & Docker Compose
- PHP 8.2+
- Laravel 12+
- Composer
- Node.js & NPM (for asset building)

### Microsoft Entra ID Setup

1. **Access Admin Center**: Go to [Microsoft Entra Admin Center](https://entra.microsoft.com/)
2. **Create App Registration**:
   - Navigate to **Identity** > **Applications** > **App registrations**
   - Click **"New registration"**
   - Name: `Your App Name`
   - Account types: Choose appropriate option
   - Redirect URI: `https://your-domain.com/auth/callback`

3. **Configure Application**:
   - Copy **Application (client) ID** → `MICROSOFT_CLIENT_ID`
   - Copy **Directory (tenant) ID** → `MICROSOFT_TENANT_ID`
   - Go to **Certificates & secrets** → Create new secret → `MICROSOFT_CLIENT_SECRET`

4. **Set API Permissions**:
   - **Microsoft Graph** > **Delegated permissions**:
     - `User.Read`
     - `profile`
     - `email` 
     - `openid`
   - Click **"Grant admin consent"**

## Microsoft Login Service Setup

### 1. Clone and Configure

```bash
git clone https://github.com/dcplibrary/microsoft-login-service.git
cd microsoft-login-service
cp .env.example .env
```

### 2. Configure Environment

Edit `.env` with your Microsoft credentials:

```env
# Application Configuration
APP_NAME="Microsoft Login Service"
APP_ENV=production
APP_DEBUG=false
APP_URL=https://your-login-service.com

# Microsoft OAuth (Required)
MICROSOFT_CLIENT_ID=your_client_id_here
MICROSOFT_CLIENT_SECRET=your_client_secret_here
MICROSOFT_TENANT_ID=your_tenant_id_here
MICROSOFT_REDIRECT_URI=https://your-login-service.com/auth/callback

# Service Configuration  
SERVICE_PORT=8080
SERVICE_HOST=0.0.0.0

# Database (SQLite by default)
DB_CONNECTION=sqlite
DB_DATABASE=/var/www/html/database/database.sqlite

# Session & Cache
SESSION_DRIVER=database
QUEUE_CONNECTION=database
CACHE_STORE=database

# CORS Configuration
CORS_ALLOWED_ORIGINS=https://your-app1.com,https://your-app2.com
CORS_ALLOWED_METHODS=GET,POST,PUT,DELETE,OPTIONS
CORS_ALLOWED_HEADERS=Content-Type,Authorization,X-Requested-With
```

### 3. Deploy with Docker

```bash
# Production deployment
docker-compose up -d

# Development with MySQL
docker-compose --profile dev up -d
```

### 4. Verify Deployment

```bash
# Health check
curl https://your-login-service.com/health

# JWKS endpoint
curl https://your-login-service.com/.well-known/jwks.json
```

## Client Application Setup

### 1. Install Package

```bash
composer require dcplibrary/laravel-microsoft-sso
```

### 2. Environment Configuration

Add to your `.env`:

```env
# Microsoft Login Service Configuration
ENTRA_ISSUER=https://your-login-service.com
ENTRA_JWKS_URI=https://your-login-service.com/.well-known/jwks.json
ENTRA_AUDIENCE=your-app-name
MICROSOFT_LOGIN_URL=https://your-login-service.com
```

### 3. Configuration File

Create `config/entra-auth.php`:

```php
<?php

return [
    // Expected audience (your application identifier)
    'audience' => env('ENTRA_AUDIENCE', 'your-app'),
    
    // JWT issuer (Microsoft Login Service URL)
    'issuer' => env('ENTRA_ISSUER', 'https://your-login-service.com'),
    
    // JWKS endpoint for JWT validation
    'jwks_uri' => env('ENTRA_JWKS_URI', 'https://your-login-service.com/.well-known/jwks.json'),
    
    // Cache TTL for JWKS (seconds)
    'cache_ttl' => env('ENTRA_JWKS_CACHE_TTL', 3600),
    
    // Optional authentication (allow unauthenticated requests)
    'optional' => env('ENTRA_OPTIONAL', false),
];
```

### 4. Controllers

#### Login Controller

```php
<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Http\RedirectResponse;

/**
 * Handles user login redirection to Microsoft Login Service
 */
class LoginController extends Controller
{
    /**
     * Display the login page with Microsoft login URL
     *
     * @return \Illuminate\View\View
     */
    public function showLogin()
    {
        $loginUrl = $this->generateMicrosoftLoginUrl();
        
        return view('login', compact('loginUrl'));
    }
    
    /**
     * Generate Microsoft login URL with proper return parameters
     *
     * @return string
     */
    private function generateMicrosoftLoginUrl(): string
    {
        $clientBase = rtrim(config('app.url'), '/');
        $loginBase = rtrim(env('MICROSOFT_LOGIN_URL'), '/');
        
        // SSO callback endpoint in this app
        $to = $clientBase . '/sso/login';
        
        // Application audience identifier
        $aud = config('entra-auth.audience');
        
        // Where to redirect after successful login
        $redirect = $clientBase . '/dashboard';
        
        // Build the complete login URL
        $returnTo = $loginBase . '/sso/forward?' . http_build_query([
            'to' => $to,
            'aud' => $aud,
            'redirect' => $redirect,
        ]);
        
        return $loginBase . '/login/microsoft?' . http_build_query([
            'returnTo' => $returnTo,
        ]);
    }
}
```

#### SSO Login Controller

```php
<?php

namespace App\Http\Controllers;

use App\Models\User;
use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Illuminate\Http\Request;
use Illuminate\Http\RedirectResponse;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Str;

/**
 * Handles SSO login with JWT token validation
 */
class SsoLoginController extends Controller
{
    /**
     * Process SSO login with JWT token
     *
     * @param Request $request
     * @return RedirectResponse
     * @throws \Exception
     */
    public function login(Request $request): RedirectResponse
    {
        $jwt = $request->query('token');
        
        if (empty($jwt)) {
            abort(400, 'JWT token is required');
        }
        
        try {
            // Validate and decode JWT token
            $claims = $this->validateJwtToken($jwt);
            
            // Create or update user
            $user = $this->createOrUpdateUser($claims);
            
            // Login user
            Auth::login($user, remember: true);
            
            // Redirect to intended destination
            $redirect = $request->query('redirect', '/dashboard');
            return redirect()->to($redirect);
            
        } catch (\Exception $e) {
            \Log::error('SSO Login failed', [
                'error' => $e->getMessage(),
                'token' => substr($jwt, 0, 50) . '...',
            ]);
            
            return redirect('/login')->withErrors([
                'sso' => 'Authentication failed. Please try again.'
            ]);
        }
    }
    
    /**
     * Validate JWT token using JWKS
     *
     * @param string $jwt
     * @return array Token claims
     * @throws \Exception
     */
    private function validateJwtToken(string $jwt): array
    {
        // Fetch JWKS with caching
        $jwks = $this->fetchJwks();
        
        // Parse JWKS keys
        $keys = JWK::parseKeySet($jwks);
        
        // Decode and validate JWT
        $decoded = JWT::decode($jwt, $keys);
        $claims = (array) $decoded;
        
        // Validate issuer and audience
        $expectedIssuer = config('entra-auth.issuer');
        $expectedAudience = config('entra-auth.audience');
        
        if (($claims['iss'] ?? null) !== $expectedIssuer) {
            throw new \Exception('Invalid JWT issuer');
        }
        
        if (($claims['aud'] ?? null) !== $expectedAudience) {
            throw new \Exception('Invalid JWT audience');
        }
        
        return $claims;
    }
    
    /**
     * Fetch JWKS with caching
     *
     * @return array
     * @throws \Exception
     */
    private function fetchJwks(): array
    {
        $cacheKey = 'entra_jwks';
        $cacheTtl = config('entra-auth.cache_ttl', 3600);
        
        return Cache::remember($cacheKey, $cacheTtl, function () {
            $jwksUri = config('entra-auth.jwks_uri');
            
            $context = stream_context_create([
                'http' => [
                    'timeout' => 10,
                    'method' => 'GET',
                ],
            ]);
            
            $response = file_get_contents($jwksUri, false, $context);
            
            if ($response === false) {
                throw new \Exception('Failed to fetch JWKS');
            }
            
            $jwks = json_decode($response, true);
            
            if (json_last_error() !== JSON_ERROR_NONE) {
                throw new \Exception('Invalid JWKS JSON');
            }
            
            return $jwks;
        });
    }
    
    /**
     * Create or update user from JWT claims
     *
     * @param array $claims
     * @return User
     */
    private function createOrUpdateUser(array $claims): User
    {
        $email = $claims['email'] ?? null;
        $name = $claims['name'] ?? null;
        
        if (empty($email)) {
            throw new \Exception('Email claim is required');
        }
        
        return User::firstOrCreate(
            ['email' => $email],
            [
                'name' => $name ?: $email,
                'password' => Str::password(32), // Random password
            ]
        );
    }
}
```

### 5. Routes

```php
<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\LoginController;
use App\Http\Controllers\SsoLoginController;

// Public routes
Route::get('/login', [LoginController::class, 'showLogin'])->name('login');
Route::get('/sso/login', [SsoLoginController::class, 'login'])->name('sso.login');

// Protected routes
Route::middleware(['sso.auto'])->group(function () {
    Route::get('/dashboard', function () {
        return view('dashboard');
    })->name('dashboard');
    
    Route::get('/profile', function () {
        return view('profile');
    })->name('profile');
});

// API routes with JWT validation
Route::middleware(['entra.auth'])->prefix('api')->group(function () {
    Route::get('/user', function (Request $request) {
        return response()->json([
            'claims' => $request->attributes->get('entra_claims'),
        ]);
    });
});
```

### 6. Views

#### Login View (`resources/views/login.blade.php`)

```blade
<!DOCTYPE html>
<html>
<head>
    <title>Login - {{ config('app.name') }}</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { 
            font-family: Arial, sans-serif; 
            max-width: 400px; 
            margin: 100px auto; 
            padding: 20px; 
            text-align: center;
        }
        .login-btn {
            display: inline-block;
            background: #0078d4;
            color: white;
            padding: 12px 24px;
            text-decoration: none;
            border-radius: 4px;
            margin: 20px 0;
        }
        .login-btn:hover { background: #106ebe; }
        .error { color: #d32f2f; margin: 10px 0; }
    </style>
</head>
<body>
    <h1>Welcome to {{ config('app.name') }}</h1>
    <p>Please sign in with your Microsoft account to continue.</p>
    
    @if($errors->any())
        <div class="error">
            {{ $errors->first() }}
        </div>
    @endif
    
    <a href="{{ $loginUrl }}" class="login-btn">
        Sign in with Microsoft
    </a>
    
    <p><small>You'll be redirected to Microsoft to authenticate, then back here.</small></p>
</body>
</html>
```

#### Dashboard View (`resources/views/dashboard.blade.php`)

```blade
<!DOCTYPE html>
<html>
<head>
    <title>Dashboard - {{ config('app.name') }}</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { 
            font-family: Arial, sans-serif; 
            max-width: 800px; 
            margin: 50px auto; 
            padding: 20px; 
        }
        .nav {
            background: #0078d4;
            color: white;
            padding: 15px;
            border-radius: 4px;
            margin-bottom: 20px;
        }
        .user-info {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            margin: 20px 0;
        }
        .success { color: #28a745; }
    </style>
</head>
<body>
    <div class="nav">
        <h1>{{ config('app.name') }} Dashboard</h1>
        <p>Welcome, you are successfully authenticated!</p>
    </div>

    <div class="user-info">
        <h3 class="success">✅ Authentication Successful</h3>
        @auth
            <p><strong>Logged in as:</strong> {{ auth()->user()->name }}</p>
            <p><strong>Email:</strong> {{ auth()->user()->email }}</p>
        @else
            <p>Session authenticated through SSO</p>
        @endauth
    </div>
</body>
</html>
```

## Configuration

### Environment Variables

#### Microsoft Login Service

| Variable | Description | Example |
|----------|-------------|---------|
| `MICROSOFT_CLIENT_ID` | Azure AD Client ID | `abc123...` |
| `MICROSOFT_CLIENT_SECRET` | Azure AD Secret | `xyz789...` |
| `MICROSOFT_TENANT_ID` | Azure AD Tenant ID | `common` or GUID |
| `MICROSOFT_REDIRECT_URI` | OAuth callback URL | `https://service.com/auth/callback` |
| `SERVICE_PORT` | Service port | `8080` |
| `CORS_ALLOWED_ORIGINS` | Allowed client origins | `https://app1.com,https://app2.com` |

#### Client Application

| Variable | Description | Example |
|----------|-------------|---------|
| `ENTRA_ISSUER` | Login service URL | `https://login-service.com` |
| `ENTRA_JWKS_URI` | JWKS endpoint | `https://login-service.com/.well-known/jwks.json` |
| `ENTRA_AUDIENCE` | App identifier | `my-app` |
| `MICROSOFT_LOGIN_URL` | Login service base URL | `https://login-service.com` |

## API Reference

### Microsoft Login Service Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/login/microsoft` | GET | Initiate Microsoft OAuth |
| `/auth/callback` | GET | OAuth callback |
| `/logout` | POST | Logout user |
| `/sso/forward` | GET | Forward with JWT token |
| `/sso/token` | GET/POST | Generate JWT token |
| `/.well-known/jwks.json` | GET | JWT validation keys |

### Client Application Routes

| Route | Middleware | Description |
|-------|------------|-------------|
| `/login` | - | Login page |
| `/sso/login` | - | SSO callback |
| `/dashboard` | `sso.auto` | Protected dashboard |
| `/api/*` | `entra.auth` | API with JWT validation |

## Testing

### Automated Tests

Create a comprehensive test suite:

```php
<?php

namespace Tests\Feature;

use Tests\TestCase;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class MicrosoftSsoTest extends TestCase
{
    /**
     * Test login page displays Microsoft login button
     */
    public function test_login_page_shows_microsoft_button()
    {
        $response = $this->get('/login');
        
        $response->assertStatus(200)
                 ->assertSee('Sign in with Microsoft')
                 ->assertSee(config('entra-auth.issuer'));
    }
    
    /**
     * Test SSO login with valid JWT token
     */
    public function test_sso_login_with_valid_token()
    {
        $token = $this->generateTestJwt();
        
        $response = $this->get("/sso/login?token={$token}&redirect=/dashboard");
        
        $response->assertRedirect('/dashboard');
        $this->assertAuthenticatedAs(User::where('email', 'test@example.com')->first());
    }
    
    /**
     * Test SSO login rejects invalid token
     */
    public function test_sso_login_rejects_invalid_token()
    {
        $invalidToken = 'invalid.jwt.token';
        
        $response = $this->get("/sso/login?token={$invalidToken}");
        
        $response->assertRedirect('/login')
                 ->assertSessionHasErrors(['sso']);
    }
    
    /**
     * Test protected route redirects unauthenticated users
     */
    public function test_protected_route_requires_authentication()
    {
        $response = $this->get('/dashboard');
        
        $response->assertRedirect('/login');
    }
    
    /**
     * Generate a test JWT token for testing
     */
    private function generateTestJwt(): string
    {
        $payload = [
            'iss' => config('entra-auth.issuer'),
            'aud' => config('entra-auth.audience'),
            'sub' => '123',
            'email' => 'test@example.com',
            'name' => 'Test User',
            'iat' => time(),
            'exp' => time() + 300,
        ];
        
        $privateKey = $this->getTestPrivateKey();
        
        return JWT::encode($payload, $privateKey, 'RS256');
    }
    
    /**
     * Get test private key for JWT signing
     */
    private function getTestPrivateKey(): string
    {
        return file_get_contents(base_path('tests/fixtures/test-private-key.pem'));
    }
}
```

### Manual Testing Checklist

#### Basic Flow Testing

- [ ] **Login Page**: Visit `/login` - should show Microsoft login button
- [ ] **Microsoft OAuth**: Click login - should redirect to Microsoft
- [ ] **Authentication**: Complete Microsoft login - should redirect back
- [ ] **Dashboard Access**: Should access protected `/dashboard` route
- [ ] **User Info**: Should display correct user name and email

#### Security Testing

- [ ] **Invalid Token**: Try accessing `/sso/login` with invalid token - should fail
- [ ] **Expired Token**: Use expired JWT - should reject
- [ ] **Wrong Audience**: Use JWT with different audience - should reject  
- [ ] **Wrong Issuer**: Use JWT from different issuer - should reject
- [ ] **Protected Routes**: Access `/dashboard` without auth - should redirect

#### Integration Testing  

- [ ] **JWKS Endpoint**: Verify `/.well-known/jwks.json` returns valid keys
- [ ] **Service Health**: Check `/health` endpoint responds
- [ ] **CORS**: Test from different domains (if configured)
- [ ] **Multiple Apps**: Test with multiple client applications

### Load Testing

Test the service under load:

```bash
# Install Apache Bench
sudo apt-get install apache2-utils

# Test login service health endpoint
ab -n 1000 -c 10 http://your-login-service.com/health

# Test JWKS endpoint
ab -n 500 -c 5 http://your-login-service.com/.well-known/jwks.json
```

## Troubleshooting

### Common Issues

#### 1. "kid" invalid, unable to lookup correct key

**Cause**: JWT token key ID doesn't match JWKS keys  
**Solution**:
1. Verify JWKS endpoint: `curl https://login-service.com/.well-known/jwks.json`
2. Clear Laravel cache: `php artisan cache:clear`
3. Restart Microsoft Login Service
4. Try fresh login to get new token

#### 2. JWT token expired

**Cause**: Token has exceeded 5-minute expiry  
**Solution**: Login again to get fresh token

#### 3. Invalid issuer or audience

**Cause**: Configuration mismatch between service and client  
**Solution**: Verify `ENTRA_ISSUER` and `ENTRA_AUDIENCE` match service configuration

#### 4. CORS errors

**Cause**: Client domain not in allowed origins  
**Solution**: Add client domain to `CORS_ALLOWED_ORIGINS` in service

#### 5. Service not responding

**Cause**: Docker container not running or networking issues  
**Solution**:
```bash
docker-compose ps
docker-compose logs microsoft-login-service
docker-compose restart microsoft-login-service
```

### Debug Tools

#### JWT Debug Script

```php
<?php
// debug-jwt.php
require_once 'vendor/autoload.php';

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;

$jwt = 'paste_your_jwt_token_here';
$jwksUrl = 'https://your-login-service.com/.well-known/jwks.json';

// Decode header
$parts = explode('.', $jwt);
$header = json_decode(base64_decode($parts[0]), true);
echo "JWT Kid: {$header['kid']}\n";

// Fetch JWKS
$jwks = json_decode(file_get_contents($jwksUrl), true);
echo "JWKS Keys: " . implode(', ', array_column($jwks['keys'], 'kid')) . "\n";

// Validate
try {
    $keys = JWK::parseKeySet($jwks);
    $decoded = JWT::decode($jwt, $keys);
    echo "✅ Token valid\n";
} catch (Exception $e) {
    echo "❌ Token invalid: {$e->getMessage()}\n";
}
```

### Monitoring

#### Health Checks

Set up monitoring for:
- Microsoft Login Service health: `/health`
- JWKS endpoint availability: `/.well-known/jwks.json`
- Client app authentication flow
- JWT token validation success rate

#### Logging

Enable logging in both services:

```php
// In SsoLoginController
\Log::info('SSO login attempt', [
    'user_email' => $claims['email'] ?? 'unknown',
    'client_ip' => $request->ip(),
    'user_agent' => $request->userAgent(),
]);
```

## Production Deployment

### Security Checklist

- [ ] **HTTPS Only**: Use HTTPS for all endpoints
- [ ] **Secure Cookies**: Configure secure session cookies
- [ ] **CORS**: Restrict CORS to specific domains
- [ ] **Rate Limiting**: Implement rate limiting on auth endpoints
- [ ] **Logging**: Enable security event logging
- [ ] **Secrets Management**: Use environment variables or vault
- [ ] **Container Security**: Use non-root containers
- [ ] **Network Security**: Use private networks for inter-service communication

### Docker Compose Production

```yaml
version: '3.8'
services:
  microsoft-login-service:
    image: your-registry/microsoft-login-service:latest
    restart: unless-stopped
    environment:
      - APP_ENV=production
      - APP_DEBUG=false
      - APP_URL=https://login.yourcompany.com
    volumes:
      - jwt_keys:/var/www/html/storage/app
      - ./logs:/var/www/html/storage/logs
    networks:
      - app-network
    
  nginx:
    image: nginx:alpine
    ports:
      - "443:443"
      - "80:80"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./ssl:/etc/ssl/certs
    depends_on:
      - microsoft-login-service
    networks:
      - app-network

networks:
  app-network:
    driver: bridge

volumes:
  jwt_keys:
```

### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: microsoft-login-service
spec:
  replicas: 3
  selector:
    matchLabels:
      app: microsoft-login-service
  template:
    metadata:
      labels:
        app: microsoft-login-service
    spec:
      containers:
      - name: microsoft-login-service
        image: your-registry/microsoft-login-service:latest
        ports:
        - containerPort: 8080
        env:
        - name: MICROSOFT_CLIENT_ID
          valueFrom:
            secretKeyRef:
              name: microsoft-oauth-secret
              key: client-id
        - name: MICROSOFT_CLIENT_SECRET
          valueFrom:
            secretKeyRef:
              name: microsoft-oauth-secret
              key: client-secret
        volumeMounts:
        - name: jwt-keys
          mountPath: /var/www/html/storage/app
      volumes:
      - name: jwt-keys
        persistentVolumeClaim:
          claimName: jwt-keys-pvc
---
apiVersion: v1
kind: Service
metadata:
  name: microsoft-login-service
spec:
  selector:
    app: microsoft-login-service
  ports:
  - port: 80
    targetPort: 8080
  type: ClusterIP
```

## Advanced Usage

### Multiple Client Applications

Configure multiple apps to use the same login service:

```bash
# App 1 environment
ENTRA_AUDIENCE=app1
MICROSOFT_LOGIN_URL=https://login.company.com

# App 2 environment  
ENTRA_AUDIENCE=app2
MICROSOFT_LOGIN_URL=https://login.company.com

# Service CORS configuration
CORS_ALLOWED_ORIGINS=https://app1.company.com,https://app2.company.com
```

### Custom Middleware

Create custom middleware for specific requirements:

```php
<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;

/**
 * Custom SSO middleware with additional validation
 */
class CustomSsoMiddleware
{
    /**
     * Handle an incoming request
     *
     * @param Request $request
     * @param Closure $next
     * @return mixed
     */
    public function handle(Request $request, Closure $next)
    {
        // Custom validation logic
        if (!$this->validateUserAccess($request)) {
            return redirect('/access-denied');
        }
        
        return $next($request);
    }
    
    /**
     * Custom user access validation
     *
     * @param Request $request
     * @return bool
     */
    private function validateUserAccess(Request $request): bool
    {
        $user = $request->user();
        
        // Add custom business logic
        return $user && $user->hasRole('admin');
    }
}
```

### API Token Generation

For API access, generate tokens programmatically:

```php
<?php

namespace App\Http\Controllers\Api;

use Illuminate\Http\Request;
use Illuminate\Http\JsonResponse;

/**
 * API token generation controller
 */
class TokenController extends Controller
{
    /**
     * Generate API token for authenticated user
     *
     * @param Request $request
     * @return JsonResponse
     */
    public function generateToken(Request $request): JsonResponse
    {
        if (!$request->user()) {
            return response()->json(['error' => 'Unauthenticated'], 401);
        }
        
        // Get token from Microsoft Login Service
        $tokenUrl = config('entra-auth.issuer') . '/sso/token';
        
        $response = Http::withCookies($request->cookies->all())
                       ->get($tokenUrl);
        
        if ($response->successful()) {
            return response()->json([
                'token' => $response->body(),
                'expires_in' => 300, // 5 minutes
            ]);
        }
        
        return response()->json(['error' => 'Token generation failed'], 500);
    }
}
```

## Migration Guide

### From Laravel Socialite

If migrating from Laravel Socialite:

1. **Remove Socialite**: `composer remove laravel/socialite`
2. **Install Package**: `composer require dcplibrary/laravel-microsoft-sso`
3. **Update Routes**: Replace Socialite routes with SSO routes
4. **Update Controllers**: Use JWT validation instead of Socialite user
5. **Test Integration**: Verify authentication flow works

### From Other SSO Solutions

1. **Database Migration**: Ensure user table compatibility
2. **Session Cleanup**: Clear existing sessions
3. **Configuration Update**: Update environment variables
4. **Testing**: Comprehensive testing of auth flow
5. **Rollback Plan**: Prepare rollback strategy

## Support

### Resources

- **Microsoft Login Service**: [GitHub Repository](https://github.com/dcplibrary/microsoft-login-service)
- **Laravel Microsoft SSO**: [GitHub Repository](https://github.com/dcplibrary/laravel-microsoft-sso)
- **Issues**: [GitHub Issues](https://github.com/dcplibrary/microsoft-login-service/issues)

### Community

- Submit issues on GitHub
- Contribute improvements via pull requests
- Share usage examples and best practices

---

*This guide covers comprehensive integration of Laravel Microsoft SSO with the Microsoft Login Service. For specific implementation details, refer to the code examples and test suites provided.*