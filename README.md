[![Release](https://github.com/dcplibrary/laravel-microsoft-sso/actions/workflows/release.yml/badge.svg)](https://github.com/dcplibrary/laravel-microsoft-sso/actions/workflows/release.yml)
# Laravel Microsoft SSO

A Laravel package for easy Microsoft SSO integration with an external Microsoft login service.

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

### Protecting Routes with SSO

Use the `sso.auto` middleware on routes that require authentication:

```php
use Illuminate\Support\Facades\Route;

Route::middleware(['sso.auto'])->group(function () {
    Route::get('/dashboard', function () {
        return view('dashboard');
    });
    
    Route::get('/protected', function () {
        return response()->json(['user' => auth()->user()]);
    });
});
```

### Manual Login Route

The package automatically provides login routes, but you can link to them:

```php
// Redirect users to login
return redirect()->route('microsoft-sso.login');
```

### Customizing Views

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

## Configuration Options

All configuration options in `config/microsoft-sso.php`:

| Option | Default | Description |
|--------|---------|-------------|
| `login_service_url` | `http://localhost:8080` | URL of your Microsoft login service |
| `issuer` | Same as login_service_url | Expected JWT issuer |
| `jwks_uri` | `{login_service_url}/.well-known/jwks.json` | JWKS endpoint |
| `audience` | App name | Expected JWT audience |
| `redirect_after_login` | `/dashboard` | Where to redirect after login |

## Requirements

- Laravel 10.x or higher
- PHP 8.1+
- External Microsoft Login Service (separate Laravel app)
- `firebase/php-jwt` package (automatically installed)

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

## License

MIT License
