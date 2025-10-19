# WARP.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.

Project type: Laravel package providing Microsoft SSO via an external login service and JWT verification.

Commands

- Install dependencies
  ```bash
  composer install
  ```
- Optimize autoloaders (after changing namespaces or classes)
  ```bash
  composer dump-autoload -o
  ```
- Run tests (uses PHPUnit + Orchestra Testbench when tests are added under tests/)
  ```bash
  ./vendor/bin/phpunit
  ```
- Run a single test file or method
  ```bash
  ./vendor/bin/phpunit tests/Feature/ExampleTest.php
  ./vendor/bin/phpunit --filter ExampleTest::it_does_something
  ```
- In a consuming Laravel app: publish package assets
  ```bash
  php artisan vendor:publish --tag=microsoft-sso-config
  php artisan vendor:publish --tag=microsoft-sso-views
  ```

High-level architecture

- Service Provider: DcpLibrary\MicrosoftSso\Providers\MicrosoftSsoServiceProvider
  - Merges config, loads routes and views, and publishes config and views for customization.
  - Registers middleware alias sso.auto -> DcpLibrary\MicrosoftSso\Http\Middleware\EnsureSso.
- Routes: routes/web.php
  - Prefix microsoft-sso with two GET endpoints and named routes:
    - GET /microsoft-sso/login -> microsoft-sso.login
    - GET /microsoft-sso/callback -> microsoft-sso.callback
- Middleware: EnsureSso
  - Gatekeeping middleware that allows authenticated users through; unauthenticated users are redirected to microsoft-sso.login.
- Controllers
  - LoginController@showLogin: Builds a returnTo flow to the external Microsoft Login Service using config values. Renders view microsoft-sso::login with a computed $loginUrl.
  - SsoCallbackController@callback: Validates JWT returned from the external service using JWKS (firebase/php-jwt). Verifies iss and aud, maps user by email into App\Models\User (firstOrCreate), logs in via Auth::login, and redirects to configured location.
- Views: resources/views/login.blade.php (loaded under the microsoft-sso namespace; publishable to resources/views/vendor/microsoft-sso/ in an app).
- Configuration: config/microsoft-sso.php (env-driven)
  - MICROSOFT_LOGIN_URL: external login service base URL
  - MICROSOFT_SSO_ISSUER: expected JWT issuer (defaults to login URL)
  - MICROSOFT_SSO_JWKS_URI: JWKS endpoint for signature validation
  - MICROSOFT_SSO_AUDIENCE: expected audience (defaults to app name)
  - MICROSOFT_SSO_REDIRECT: post-login redirect path
  - MICROSOFT_SSO_CACHE_TTL: JWKS cache TTL (seconds)
- Dependencies (composer.json)
  - Runtime: illuminate/support, illuminate/routing, firebase/php-jwt
  - Dev: phpunit/phpunit, orchestra/testbench

Notes for working locally

- This is a package, not a full Laravel app. To exercise the flow end-to-end, require it in a Laravel application (via Packagist or a path repository), publish config/views, set the environment variables above, and protect routes with the sso.auto middleware.
