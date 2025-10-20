<?php

namespace DcpLibrary\MicrosoftSso\Tests;

use DcpLibrary\MicrosoftSso\Providers\MicrosoftSsoServiceProvider;
use Firebase\JWT\JWT;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Orchestra\Testbench\TestCase as Orchestra;

abstract class TestCase extends Orchestra
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();

        $this->loadLaravelMigrations();
        
        // Set up test configuration
        config([
            'microsoft-sso.login_service_url' => 'http://localhost:8080',
            'microsoft-sso.issuer' => 'http://localhost:8080',
            'microsoft-sso.jwks_uri' => 'http://localhost:8080/.well-known/jwks.json',
            'microsoft-sso.audience' => 'test-app',
            'microsoft-sso.redirect_after_login' => '/dashboard',
        ]);
    }

    /**
     * Get package providers.
     *
     * @param Application $app
     * @return array<int, class-string>
     */
    protected function getPackageProviders($app): array
    {
        return [
            MicrosoftSsoServiceProvider::class,
        ];
    }

    /**
     * Define environment setup.
     *
     * @param Application $app
     */
    protected function defineEnvironment($app): void
    {
        $app['config']->set('database.default', 'testing');
        $app['config']->set('database.connections.testing', [
            'driver' => 'sqlite',
            'database' => ':memory:',
            'prefix' => '',
        ]);
    }

    /**
     * Generate a test JWT token
     *
     * @param array $claims
     * @return string
     */
    protected function generateTestJwt(array $claims = []): string
    {
        $defaultClaims = [
            'iss' => config('microsoft-sso.issuer'),
            'aud' => config('microsoft-sso.audience'),
            'sub' => 'test-user',
            'email' => 'test@example.com',
            'name' => 'Test User',
            'iat' => time(),
            'exp' => time() + 300, // 5 minutes
        ];

        $payload = array_merge($defaultClaims, $claims);
        
        // Use a test private key
        $privateKey = $this->getTestPrivateKey();
        
        return JWT::encode($payload, $privateKey, 'RS256');
    }

    /**
     * Get test RSA private key for JWT signing
     *
     * @return string
     */
    protected function getTestPrivateKey(): string
    {
        // This is a test-only RSA private key - DO NOT use in production
        return '-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEjWT2btPN9
PoaInqBV7hd26gT0qNRpQC5VsaKzGd/cQLkIJDJn1QcOQpx8UDtM9KAJJYcKmJGG
cIBGhqWxr2rM4t6JrLWMa8GRxnK2KlTm/iOu+v2YZjGK3HVaJu8v5G2wTT7P7L8
MgXZZQ8J4h3sA+1Nd1cKp/F5qH1Q+sI7c8vbwKc+dG8zGbF3aJY8tEz9x8u7B8
VhYVG5jY+bF8P8Yf2rF2t9MqQU2QoQP/PGxQXuAYtS1zZ1KDHvYwgk8K7J4G/lE
7R8nKn5F/c+GcJJZm/KxmVlE4XqUhpH/5L7Kz/V8wIDAQABAoIBAGsR6z5vDKlO
6OVXUhKwj5k5TQN7ht8gGH1Tq1lhFG5o3c3y8a4lFq6gCZa5yUGpTJ9KF9KHKcH
Qj+N4k6vp0qP+hKf9L+TLJ0Km9Y3xK9nJ0X+bYo4KjYoW0T6U8gF1L1sK2H+j9l
5vC8R8Y2vK8G1GJ3j5wC5q6F1K3+VHzMKz0Q3hf+3wQl1Kz1k+OUf4K+r1H+Jzh
aLF8d0t/G6YK+YnL7Km+WL+qj4Bj+2F9R7+3L0k8y2vT0fJ+RxN0fJ+5k8L+0P+
9l4Y7KZ3H0L+L0Lz4wKBgQDt/xY5X8VhKQKBgQDC5J7Z0Y0vK2F4KQ8G5K+H+Qzh
Ly5o1v4P0KvBl8gF1vJ4n6l4WjP8W2jU7Q5U1N4Y+0g4V0vW8A+kFG2Kj+y0wKzm
M+q1z1H0J4Z3v0V8s9lF8tU4uK5gH4wKBgBqK1T4I1cQ3Y2fJ4t4g4m8Y3L4U8F
2M2Y1j4K8F4z8i+l4J4p4d4T0U1D4u7Nm4F8oFKBgHl4v1a4Y+l4d8u4t4K8K4F
7T8Y1j4K8F4z8i+l4J4p4d4T0U1D4u7Nm4F8oF
-----END RSA PRIVATE KEY-----';
    }

    /**
     * Get test RSA public key (corresponding to private key)
     *
     * @return string
     */
    protected function getTestPublicKey(): string
    {
        return '-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4f5wg5l2hKsTeNem/V41
fGnJm6gOdrj8ym3rFkEjWT2btPN9PoaInqBV7hd26gT0qNRpQC5VsaKzGd/cQLkI
JDJn1QcOQpx8UDtM9KAJJYcKmJGGcIBGhqWxr2rM4t6JrLWMa8GRxnK2KlTm/iOu
+v2YZjGK3HVaJu8v5G2wTT7P7L8MgXZZQ8J4h3sA+1Nd1cKp/F5qH1Q+sI7c8vbw
Kc+dG8zGbF3aJY8tEz9x8u7B8VhYVG5jY+bF8P8Yf2rF2t9MqQU2QoQP/PGxQXuA
YtS1zZ1KDHvYwgk8K7J4G/lE7R8nKn5F/c+GcJJZm/KxmVlE4XqUhpH/5L7Kz/V8
wIDAQAB
-----END PUBLIC KEY-----';
    }
}