# Laravel Microsoft SSO

A Laravel package for easy Microsoft SSO integration using JWT token authentication with an external Microsoft login service.

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
   # Microsoft Login Service Configuration
   MICROSOFT_LOGIN_URL=http://localhost:8000
   MICROSOFT_SSO_ISSUER=http://localhost:8000
   MICROSOFT_SSO_JWKS_URI=http://localhost:8000/.well-known/jwks.json
   MICROSOFT_SSO_AUDIENCE=your-app-name
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
| `login_service_url` | `http://localhost:8000` | URL of your Microsoft login service |
| `issuer` | Same as login_service_url | Expected JWT issuer |
| `jwks_uri` | `{login_service_url}/.well-known/jwks.json` | JWKS endpoint |
| `audience` | App name | Expected JWT audience |
| `redirect_after_login` | `/dashboard` | Where to redirect after login |

## Requirements

- Laravel 10.x or 11.x
- PHP 8.1+
- External Microsoft Login Service (separate Laravel app)
- `firebase/php-jwt` package (automatically installed)

## Microsoft Login Service

This package requires a separate Microsoft Login Service (another Laravel app) that:
- Handles OAuth with Microsoft
- Issues JWT tokens
- Provides JWKS endpoint

## License

MIT License