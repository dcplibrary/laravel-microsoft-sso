<?php

namespace DcpLibrary\MicrosoftSso\Http\Middleware;

use Closure;
use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;

/**
 * JWT Authentication Middleware for API routes
 * 
 * Validates JWT tokens from Authorization header without creating user sessions.
 * Perfect for API endpoints that need stateless authentication.
 */
class EntraAuth
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
        $jwt = $this->extractJwtFromRequest($request);
        
        if (!$jwt) {
            return response()->json(['error' => 'JWT token required'], 401);
        }

        try {
            $claims = $this->validateJwtToken($jwt);
            
            // Store claims in request for controllers to access
            $request->attributes->set('entra_claims', $claims);
            $request->attributes->set('entra_user_email', $claims['email'] ?? null);
            $request->attributes->set('entra_user_name', $claims['name'] ?? null);
            
            return $next($request);
            
        } catch (\Exception $e) {
            Log::warning('JWT validation failed', [
                'error' => $e->getMessage(),
                'token' => substr($jwt, 0, 50) . '...',
                'ip' => $request->ip(),
            ]);
            
            return response()->json(['error' => 'Invalid JWT token'], 401);
        }
    }

    /**
     * Extract JWT token from Authorization header
     *
     * @param Request $request
     * @return string|null
     */
    private function extractJwtFromRequest(Request $request): ?string
    {
        $authHeader = $request->header('Authorization');
        
        if (!$authHeader || !str_starts_with($authHeader, 'Bearer ')) {
            return null;
        }
        
        return substr($authHeader, 7); // Remove 'Bearer ' prefix
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
        $expectedIssuer = config('microsoft-sso.issuer');
        $expectedAudience = config('microsoft-sso.audience');
        
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
        $cacheKey = 'microsoft_sso_jwks';
        $cacheTtl = config('microsoft-sso.jwks_cache_ttl', 3600);
        
        return Cache::remember($cacheKey, $cacheTtl, function () {
            $jwksUri = config('microsoft-sso.jwks_uri');
            
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
}