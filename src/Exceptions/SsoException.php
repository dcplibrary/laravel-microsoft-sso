<?php

namespace DcpLibrary\MicrosoftSso\Exceptions;

use Exception;

/**
 * Base exception class for Microsoft SSO package
 */
class SsoException extends Exception
{
    //
}

/**
 * Exception thrown when JWT token validation fails
 */
class InvalidJwtException extends SsoException
{
    public static function invalidFormat(): self
    {
        return new self('JWT token has invalid format');
    }

    public static function expired(): self
    {
        return new self('JWT token has expired');
    }

    public static function invalidSignature(): self
    {
        return new self('JWT token has invalid signature');
    }

    public static function invalidIssuer(string $expected, string $actual): self
    {
        return new self("JWT issuer mismatch. Expected: {$expected}, Got: {$actual}");
    }

    public static function invalidAudience(string $expected, string $actual): self
    {
        return new self("JWT audience mismatch. Expected: {$expected}, Got: {$actual}");
    }

    public static function missingClaim(string $claim): self
    {
        return new self("Required JWT claim '{$claim}' is missing");
    }
}

/**
 * Exception thrown when JWKS endpoint is unreachable or invalid
 */
class JwksException extends SsoException
{
    public static function unreachableEndpoint(string $uri): self
    {
        return new self("JWKS endpoint unreachable: {$uri}");
    }

    public static function invalidFormat(): self
    {
        return new self('JWKS response has invalid format');
    }

    public static function noKeysFound(): self
    {
        return new self('No keys found in JWKS response');
    }

    public static function keyNotFound(string $kid): self
    {
        return new self("Key with ID '{$kid}' not found in JWKS");
    }
}

/**
 * Exception thrown when SSO service configuration is invalid
 */
class ConfigurationException extends SsoException
{
    public static function missingConfiguration(string $key): self
    {
        return new self("Required configuration '{$key}' is missing");
    }

    public static function invalidUrl(string $url): self
    {
        return new self("Invalid URL: {$url}");
    }
}