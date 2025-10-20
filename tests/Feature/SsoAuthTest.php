<?php

namespace DcpLibrary\MicrosoftSso\Tests\Feature;

use App\Models\User;
use DcpLibrary\MicrosoftSso\Tests\TestCase;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Http;

class SsoAuthTest extends TestCase
{
    use RefreshDatabase;

    /** @test */
    public function it_shows_login_page()
    {
        $response = $this->get('/microsoft-sso/login');

        $response->assertStatus(200)
                 ->assertSee('Sign in with Microsoft')
                 ->assertSee(config('microsoft-sso.login_service_url'));
    }

    /** @test */
    public function it_redirects_unauthenticated_users_to_login()
    {
        $response = $this->get('/test-protected');

        $response->assertRedirect('/microsoft-sso/login');
    }

    /** @test */
    public function it_authenticates_user_with_valid_jwt_token()
    {
        // Mock JWKS endpoint
        Http::fake([
            config('microsoft-sso.jwks_uri') => Http::response([
                'keys' => [
                    [
                        'kid' => 'test-key-id',
                        'kty' => 'RSA',
                        'alg' => 'RS256',
                        'use' => 'sig',
                        'n' => base64url_encode(substr($this->getTestPublicKey(), 27, -25)),
                        'e' => base64url_encode('AQAB'),
                    ]
                ]
            ])
        ]);

        $token = $this->generateTestJwt([
            'email' => 'test@example.com',
            'name' => 'Test User',
        ]);

        $response = $this->get("/microsoft-sso/callback?token={$token}&redirect=/dashboard");

        $response->assertRedirect('/dashboard');
        $this->assertAuthenticatedAs(User::where('email', 'test@example.com')->first());
    }

    /** @test */
    public function it_rejects_invalid_jwt_token()
    {
        $invalidToken = 'invalid.jwt.token';

        $response = $this->get("/microsoft-sso/callback?token={$invalidToken}");

        $response->assertStatus(400);
    }

    /** @test */
    public function it_rejects_jwt_with_wrong_audience()
    {
        Http::fake([
            config('microsoft-sso.jwks_uri') => Http::response([
                'keys' => [
                    [
                        'kid' => 'test-key-id',
                        'kty' => 'RSA',
                        'alg' => 'RS256',
                        'use' => 'sig',
                        'n' => base64url_encode(substr($this->getTestPublicKey(), 27, -25)),
                        'e' => base64url_encode('AQAB'),
                    ]
                ]
            ])
        ]);

        $token = $this->generateTestJwt([
            'aud' => 'wrong-audience',
            'email' => 'test@example.com',
        ]);

        $response = $this->get("/microsoft-sso/callback?token={$token}");

        $response->assertStatus(401);
    }

    /** @test */
    public function middleware_protects_routes()
    {
        // Define a test route with SSO middleware
        $this->app['router']->get('/test-protected', function () {
            return 'protected content';
        })->middleware('sso.auto');

        $response = $this->get('/test-protected');

        $response->assertRedirect('/microsoft-sso/login');
    }

    /** @test */
    public function middleware_allows_authenticated_users()
    {
        $user = User::factory()->create();
        $this->actingAs($user);

        // Define a test route with SSO middleware
        $this->app['router']->get('/test-protected', function () {
            return 'protected content';
        })->middleware('sso.auto');

        $response = $this->get('/test-protected');

        $response->assertStatus(200)
                 ->assertSee('protected content');
    }
}

// Helper function for base64url encoding
if (!function_exists('base64url_encode')) {
    function base64url_encode($data) {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }
}