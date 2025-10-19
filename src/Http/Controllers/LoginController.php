<?php

namespace DcpLibrary\MicrosoftSso\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Routing\Controller;

class LoginController extends Controller
{
    public function showLogin()
    {
        // Build the login URL that will redirect back to our SSO endpoint
        $clientBase = rtrim(config('app.url'), '/');
        $loginBase = rtrim(config('microsoft-sso.login_service_url'), '/');
        
        $to = $clientBase . '/microsoft-sso/callback';
        $aud = (string) config('microsoft-sso.audience');
        $redirect = $clientBase . (config('microsoft-sso.redirect_after_login') ?: '/dashboard');
        
        $returnTo = $loginBase . '/sso/forward?to=' . urlencode($to) . '&aud=' . urlencode($aud) . '&redirect=' . urlencode($redirect);
        $loginUrl = $loginBase . '/login/microsoft?returnTo=' . urlencode($returnTo);
        
        return view('microsoft-sso::login', compact('loginUrl'));
    }
}