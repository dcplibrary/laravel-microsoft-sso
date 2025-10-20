<?php

namespace DcpLibrary\MicrosoftSso\Services;

use DcpLibrary\MicrosoftSso\Exceptions\InvalidJwtException;
use DcpLibrary\MicrosoftSso\Exceptions\JwksException;
use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;

/**
 * JWT Service for token validation and management
 */
class JwtService
{
    /**
     * Validate JWT token and return claims
     *
     * @param string $jwt
     * @return array
     * @throws InvalidJwtException
     * @throws JwksException
     */
    public function validateToken(string $jwt): array
    {
        if (empty($jwt)) {
            throw InvalidJwtException::invalidFormat();
        }

        try {
            // Fetch JWKS with caching
            $jwks = $this->fetchJwks();
            
            // Parse JWKS keys
            $keys = JWK::parseKeySet($jwks);
            
            // Decode and validate JWT
            $decoded = JWT::decode($jwt, $keys);
            $claims = (array) $decoded;
            
            // Validate claims
            $this->validateClaims($claims);
            
            return $claims;
            
        } catch (\Firebase\JWT\ExpiredException $e) {
            throw InvalidJwtException::expired();
        } catch (\Firebase\JWT\SignatureInvalidException $e) {
            throw InvalidJwtException::invalidSignature();
        } catch (\Exception $e) {
            throw InvalidJwtException::invalidFormat();
        }
    }

    /**
     * Extract JWT token from Authorization header
     *
     * @param string|null $authHeader
     * @return string|null
     */
    public function extractFromAuthHeader(?string $authHeader): ?string
    {
        if (!$authHeader || !str_starts_with($authHeader, 'Bearer ')) {
            return null;
        }
        
        return substr($authHeader, 7); // Remove 'Bearer ' prefix
    }

    /**
     * Get token claims without validation (for debugging)
     *
     * @param string $jwt
     * @return array|null
     */
    public function getClaimsWithoutValidation(string $jwt): ?array
    {
        try {
            $parts = explode('.', $jwt);
            if (count($parts) !== 3) {
                return null;
            }
            
            $payload = base64_decode($parts[1]);
            return json_decode($payload, true);
        } catch (\Exception $e) {
            return null;
        }
    }

    /**
     * Get token header without validation (for debugging)
     *
     * @param string $jwt
     * @return array|null
     */
    public function getHeaderWithoutValidation(string $jwt): ?array
    {
        try {
            $parts = explode('.', $jwt);
            if (count($parts) !== 3) {
                return null;
            }
            
            $header = base64_decode($parts[0]);
            return json_decode($header, true);
        } catch (\Exception $e) {
            return null;
        }
    }

    /**
     * Check if token is expired without full validation
     *
     * @param string $jwt
     * @return bool
     */
    public function isTokenExpired(string $jwt): bool
    {
        $claims = $this->getClaimsWithoutValidation($jwt);
        
        if (!$claims || !isset($claims['exp'])) {
            return true;
        }
        
        return time() >= $claims['exp'];
    }

    /**
     * Clear JWKS cache
     *
     * @return void
     */
    public function clearJwksCache(): void
    {
        Cache::forget('microsoft_sso_jwks');
    }

    /**
     * Fetch JWKS with caching
     *
     * @return array
     * @throws JwksException
     */
    private function fetchJwks(): array
    {
        $cacheKey = 'microsoft_sso_jwks';
        $cacheTtl = config('microsoft-sso.jwks_cache_ttl', 3600);
        
        return Cache::remember($cacheKey, $cacheTtl, function () {
            $jwksUri = config('microsoft-sso.jwks_uri');
            
            if (empty($jwksUri)) {
                throw JwksException::unreachableEndpoint('JWKS URI not configured');
            }

            try {
                $response = Http::timeout(10)->get($jwksUri);
                
                if (!$response->successful()) {
                    throw JwksException::unreachableEndpoint($jwksUri);
                }
                
                $jwks = $response->json();
                
                if (!is_array($jwks) || !isset($jwks['keys']) || !is_array($jwks['keys'])) {
                    throw JwksException::invalidFormat();
                }
                
                if (empty($jwks['keys'])) {
                    throw JwksException::noKeysFound();
                }
                
                return $jwks;
                
            } catch (\Exception $e) {
                if ($e instanceof JwksException) {
                    throw $e;
                }
                throw JwksException::unreachableEndpoint($jwksUri);
            }
        });
    }

    /**
     * Validate JWT claims
     *
     * @param array $claims
     * @return void
     * @throws InvalidJwtException
     */
    private function validateClaims(array $claims): void
    {
        $expectedIssuer = config('microsoft-sso.issuer');
        $expectedAudience = config('microsoft-sso.audience');
        
        // Validate issuer
        if (empty($claims['iss'])) {
            throw InvalidJwtException::missingClaim('iss');
        }
        
        if ($claims['iss'] !== $expectedIssuer) {
            throw InvalidJwtException::invalidIssuer($expectedIssuer, $claims['iss']);
        }
        
        // Validate audience
        if (empty($claims['aud'])) {
            throw InvalidJwtException::missingClaim('aud');
        }
        
        if ($claims['aud'] !== $expectedAudience) {
            throw InvalidJwtException::invalidAudience($expectedAudience, $claims['aud']);
        }
        
        // Validate email claim
        if (empty($claims['email'])) {
            throw InvalidJwtException::missingClaim('email');
        }
    }
}