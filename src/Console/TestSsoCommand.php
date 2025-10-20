<?php

namespace DcpLibrary\MicrosoftSso\Console;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Http;

/**
 * Test SSO configuration and connectivity
 */
class TestSsoCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'microsoft-sso:test';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Test Microsoft SSO configuration and connectivity';

    /**
     * Execute the console command.
     */
    public function handle(): int
    {
        $this->info('🔍 Testing Microsoft SSO Configuration...');
        $this->newLine();

        // Test configuration
        $this->testConfiguration();
        
        // Test service connectivity
        $this->testServiceConnectivity();
        
        // Test JWKS endpoint
        $this->testJwksEndpoint();

        $this->newLine();
        $this->info('✅ SSO configuration test completed!');
        
        return Command::SUCCESS;
    }

    /**
     * Test configuration values
     */
    private function testConfiguration(): void
    {
        $this->info('📋 Configuration:');
        
        $config = [
            'Login Service URL' => config('microsoft-sso.login_service_url'),
            'Issuer' => config('microsoft-sso.issuer'),
            'JWKS URI' => config('microsoft-sso.jwks_uri'),
            'Audience' => config('microsoft-sso.audience'),
            'Redirect After Login' => config('microsoft-sso.redirect_after_login'),
            'Cache TTL' => config('microsoft-sso.jwks_cache_ttl') . ' seconds',
        ];

        foreach ($config as $key => $value) {
            if (empty($value)) {
                $this->error("   ❌ {$key}: Not configured");
            } else {
                $this->line("   ✅ {$key}: {$value}");
            }
        }
        
        $this->newLine();
    }

    /**
     * Test service connectivity
     */
    private function testServiceConnectivity(): void
    {
        $this->info('🌐 Service Connectivity:');
        
        $loginServiceUrl = config('microsoft-sso.login_service_url');
        
        if (empty($loginServiceUrl)) {
            $this->error('   ❌ Login service URL not configured');
            return;
        }

        try {
            $healthUrl = rtrim($loginServiceUrl, '/') . '/health';
            $response = Http::timeout(10)->get($healthUrl);
            
            if ($response->successful()) {
                $this->line("   ✅ Health endpoint: {$healthUrl} (Status: {$response->status()})");
            } else {
                $this->error("   ❌ Health endpoint failed: {$healthUrl} (Status: {$response->status()})");
            }
        } catch (\Exception $e) {
            $this->error("   ❌ Health endpoint error: {$e->getMessage()}");
        }

        $this->newLine();
    }

    /**
     * Test JWKS endpoint
     */
    private function testJwksEndpoint(): void
    {
        $this->info('🔑 JWKS Endpoint:');
        
        $jwksUri = config('microsoft-sso.jwks_uri');
        
        if (empty($jwksUri)) {
            $this->error('   ❌ JWKS URI not configured');
            return;
        }

        try {
            $response = Http::timeout(10)->get($jwksUri);
            
            if ($response->successful()) {
                $jwks = $response->json();
                
                if (isset($jwks['keys']) && is_array($jwks['keys'])) {
                    $keyCount = count($jwks['keys']);
                    $this->line("   ✅ JWKS endpoint: {$jwksUri}");
                    $this->line("   ✅ Keys found: {$keyCount}");
                    
                    // Show key details
                    foreach ($jwks['keys'] as $index => $key) {
                        $kid = $key['kid'] ?? 'unknown';
                        $kty = $key['kty'] ?? 'unknown';
                        $alg = $key['alg'] ?? 'unknown';
                        $this->line("     - Key #{$index}: kid={$kid}, kty={$kty}, alg={$alg}");
                    }
                } else {
                    $this->error('   ❌ Invalid JWKS format - missing keys array');
                }
            } else {
                $this->error("   ❌ JWKS endpoint failed: {$jwksUri} (Status: {$response->status()})");
            }
        } catch (\Exception $e) {
            $this->error("   ❌ JWKS endpoint error: {$e->getMessage()}");
        }
    }
}