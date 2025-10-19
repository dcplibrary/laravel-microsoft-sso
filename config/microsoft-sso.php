<?php

return [
    /*
    |--------------------------------------------------------------------------
    | Microsoft SSO Configuration
    |--------------------------------------------------------------------------
    |
    | Configuration for integrating with a Microsoft Login Service.
    | This assumes you have a separate Laravel app running the Microsoft
    | login service that handles OAuth with Microsoft and issues JWTs.
    |
    */

    // URL of your Microsoft login service (e.g., another Laravel app)
    'login_service_url' => env('MICROSOFT_LOGIN_URL', 'http://localhost:8000'),

    // Expected issuer of JWT tokens (usually same as login_service_url)
    'issuer' => env('MICROSOFT_SSO_ISSUER', env('MICROSOFT_LOGIN_URL', 'http://localhost:8000')),

    // JWKS endpoint to validate JWT signatures
    'jwks_uri' => env('MICROSOFT_SSO_JWKS_URI', env('MICROSOFT_LOGIN_URL', 'http://localhost:8000') . '/.well-known/jwks.json'),

    // Expected audience in JWT tokens (your app identifier)
    'audience' => env('MICROSOFT_SSO_AUDIENCE', env('APP_NAME', 'laravel-app')),

    // Where to redirect users after successful login
    'redirect_after_login' => env('MICROSOFT_SSO_REDIRECT', '/dashboard'),

    // Cache TTL for JWKS (seconds)
    'jwks_cache_ttl' => env('MICROSOFT_SSO_CACHE_TTL', 3600),
];