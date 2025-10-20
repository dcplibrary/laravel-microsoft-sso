[![Release](https://github.com/dcplibrary/laravel-microsoft-sso/actions/workflows/release.yml/badge.svg)](https://github.com/dcplibrary/laravel-microsoft-sso/actions/workflows/release.yml)
# Laravel Microsoft SSO

A Laravel package for easy Microsoft SSO integration with an external Microsoft login service.

📖 **[Complete Integration Guide](LARAVEL_MICROSOFT_SSO_GUIDE.md)** - Comprehensive setup, troubleshooting, and production deployment guide

## Installation

1. **Install via Composer:**
   ```bash
   composer require dcplibrary/laravel-microsoft-sso
   ```

2. **Publish the configuration file:**
   ```bash
   php artisan vendor:publish --tag=microsoft-sso-config
   ```

3. **Configure your environment variables in `.env`:**
   ```env
   # Microsoft Login Service (microsoft-login-service)
   # Set these to match the service's APP_URL and endpoints
   MICROSOFT_LOGIN_URL=http://localhost:8080
   MICROSOFT_SSO_ISSUER=http://localhost:8080
   MICROSOFT_SSO_JWKS_URI=http://localhost:8080/.well-known/jwks.json
   MICROSOFT_SSO_AUDIENCE=your-app-identifier
   MICROSOFT_SSO_REDIRECT=/dashboard
   ```

## Usage

### 1. Protecting Web Routes with SSO

Use the `sso.auto` middleware for web routes that require authentication:

```php
use Illuminate\Support\Facades\Route;

Route::middleware(['sso.auto'])->group(function () {
    Route::get('/dashboard', function () {
        return view('dashboard');
    });
    
    Route::get('/profile', function () {
        return response()->json(['user' => auth()->user()]);
    });
});
```

### 2. Protecting API Routes with JWT

Use the `entra.auth` middleware for API routes that need stateless JWT authentication:

```php
// API routes with JWT validation
Route::middleware(['entra.auth'])->prefix('api')->group(function () {
    Route::get('/user', function (Request $request) {
        return response()->json([
            'claims' => $request->attributes->get('entra_claims'),
            'email' => $request->attributes->get('entra_user_email'),
            'name' => $request->attributes->get('entra_user_name'),
        ]);
    });
    
    Route::get('/protected-data', function (Request $request) {
        $userEmail = $request->attributes->get('entra_user_email');
        return response()->json(['data' => "Hello {$userEmail}"]);
    });
});
```

For API routes, clients must include the JWT token in the Authorization header:
```bash
curl -H "Authorization: Bearer your-jwt-token" https://yourapp.com/api/user
```

### 3. Manual Login Route

The package automatically provides login routes, but you can link to them:

```php
// Redirect users to login
return redirect()->route('microsoft-sso.login');
```

### 4. Testing Configuration

Test your SSO setup with the built-in command:

```bash
php artisan microsoft-sso:test
```

This will verify:
- Configuration values
- Microsoft Login Service connectivity
- JWKS endpoint availability
- Key format validation

### 5. Using the JWT Service

Inject the JWT service for advanced token operations:

```php
use DcpLibrary\MicrosoftSso\Services\JwtService;

class ApiController extends Controller
{
    public function validateToken(Request $request, JwtService $jwtService)
    {
        $token = $jwtService->extractFromAuthHeader($request->header('Authorization'));
        
        if (!$token) {
            return response()->json(['error' => 'No token provided'], 401);
        }
        
        try {
            $claims = $jwtService->validateToken($token);
            return response()->json(['valid' => true, 'claims' => $claims]);
        } catch (\Exception $e) {
            return response()->json(['valid' => false, 'error' => $e->getMessage()], 401);
        }
    }
    
    public function debugToken(Request $request, JwtService $jwtService)
    {
        $token = $request->input('token');
        
        return response()->json([
            'header' => $jwtService->getHeaderWithoutValidation($token),
            'claims' => $jwtService->getClaimsWithoutValidation($token),
            'expired' => $jwtService->isTokenExpired($token),
        ]);
    }
}
```

### 6. Customizing Views

Publish the views to customize the login page:

```bash
php artisan vendor:publish --tag=microsoft-sso-views
```

Views will be published to `resources/views/vendor/microsoft-sso/`

## How It Works

1. **User accesses protected route** → Redirected to login page
2. **User clicks "Sign in with Microsoft"** → Redirected to external Microsoft login service
3. **After Microsoft authentication** → Service issues JWT and redirects back
4. **Package validates JWT** → Creates/logs in user and redirects to dashboard

## Middleware Options

### `sso.auto` Middleware
- **Purpose**: Web route protection with user sessions
- **Behavior**: Redirects unauthenticated users to login page
- **Usage**: Traditional web applications
- **Session**: Creates Laravel user sessions

### `entra.auth` Middleware
- **Purpose**: API route protection with JWT tokens
- **Behavior**: Returns 401 JSON response for invalid/missing tokens
- **Usage**: Stateless API endpoints
- **Session**: No session creation, stores claims in request attributes

## Configuration Options

All configuration options in `config/microsoft-sso.php`:

| Option | Default | Description |
|--------|---------|-------------|
| `login_service_url` | `http://localhost:8080` | URL of your Microsoft login service |
| `issuer` | Same as login_service_url | Expected JWT issuer |
| `jwks_uri` | `{login_service_url}/.well-known/jwks.json` | JWKS endpoint |
| `audience` | App name | Expected JWT audience |
| `redirect_after_login` | `/dashboard` | Where to redirect after login |
| `jwks_cache_ttl` | `3600` | JWKS cache TTL in seconds |

## Features

✅ **Web Authentication**: Traditional session-based authentication for web routes  
✅ **API Authentication**: Stateless JWT authentication for API endpoints  
✅ **Automatic User Creation**: Creates users from JWT claims automatically  
✅ **JWKS Caching**: Intelligent caching of JWT validation keys  
✅ **Configuration Testing**: Built-in command to test your setup  
✅ **Error Handling**: Comprehensive exception handling with detailed messages  
✅ **Laravel Integration**: Native Laravel service provider with middleware  
✅ **Security**: Validates JWT signatures, expiry, issuer, and audience  

## Requirements

- Laravel 11.x or 12.x
- PHP 8.3+
- External Microsoft Login Service (separate Laravel app)
- `firebase/php-jwt` package (automatically installed)

## Testing

Run the test suite:

```bash
composer test
```

Run static analysis:

```bash
composer phpstan
```

Check code style:

```bash
composer pint
```

## Microsoft Login Service

This package works with a companion service: Microsoft Login Service.
- Repo: https://github.com/dcplibrary/microsoft-login-service
- Purpose: Centralized Microsoft (Entra ID) OAuth that issues short‑lived RS256 JWTs and exposes JWKS for validation.
- Key endpoints used by this package:
  - GET /login/microsoft (starts OAuth; accepts returnTo)
  - GET /.well-known/jwks.json (public keys for JWT validation)
  - GET /sso/forward (mints token then forwards to your app’s /microsoft-sso/callback)

Quick setup (development):
```bash
# 1) Clone and configure
git clone https://github.com/dcplibrary/microsoft-login-service.git
cd microsoft-login-service
cp .env.example .env

# 2) Set required Microsoft Entra ID values in .env
# MICROSOFT_CLIENT_ID=...
# MICROSOFT_CLIENT_SECRET=...
# MICROSOFT_TENANT_ID=...
# MICROSOFT_REDIRECT_URI=http://localhost:8080/auth/callback

# 3) Start the service (SQLite by default)
docker-compose up -d

# 4) Verify it’s running
curl http://localhost:8080/health
curl http://localhost:8080/.well-known/jwks.json
```

Then set in your client app (this package):
```env
MICROSOFT_LOGIN_URL=http://localhost:8080
MICROSOFT_SSO_ISSUER=http://localhost:8080
MICROSOFT_SSO_JWKS_URI=http://localhost:8080/.well-known/jwks.json
MICROSOFT_SSO_AUDIENCE=your-app-identifier
```

## Documentation

- **[Complete Integration Guide](LARAVEL_MICROSOFT_SSO_GUIDE.md)** - Comprehensive guide with architecture, setup, testing, troubleshooting, and production deployment
- **[Package README](README.md)** - Quick start and basic usage (this file)

## License

MIT License
