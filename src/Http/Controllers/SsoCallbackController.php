<?php

namespace DcpLibrary\MicrosoftSso\Http\Controllers;

use App\Models\User;
use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Str;

class SsoCallbackController extends Controller
{
    public function callback(Request $request)
    {
        $jwt = (string) $request->query('token', '');
        if ($jwt === '') {
            abort(400, 'token query parameter is required');
        }

        // Fetch and parse JWKS from microsoft-login service
        $jwksUrl = config('microsoft-sso.jwks_uri');
        $jwks = json_decode((string) file_get_contents($jwksUrl), true, flags: JSON_THROW_ON_ERROR);
        $keys = JWK::parseKeySet($jwks);

        // Decode & validate signature and standard time claims
        $claims = (array) JWT::decode($jwt, $keys);

        // Validate issuer and audience
        $expectedIss = config('microsoft-sso.issuer');
        $expectedAud = config('microsoft-sso.audience');
        if (($claims['iss'] ?? null) !== $expectedIss || ($claims['aud'] ?? null) !== $expectedAud) {
            abort(401, 'invalid iss or aud');
        }

        // Map to local user
        $email = $claims['email'] ?? null;
        $name  = $claims['name'] ?? ($email ?? 'User');
        if (!$email) {
            abort(422, 'email claim required');
        }

        $user = User::firstOrCreate(
            ['email' => $email],
            ['name' => $name, 'password' => Str::password()]
        );

        Auth::login($user, remember: true);

        $redirect = (string) $request->query('redirect', config('microsoft-sso.redirect_after_login', '/dashboard'));
        return redirect()->to($redirect);
    }
}