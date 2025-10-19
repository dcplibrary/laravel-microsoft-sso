<?php

namespace DcpLibrary\MicrosoftSso\Http\Middleware;

use Closure;
use Illuminate\Http\Request;

class EnsureSso
{
    public function handle(Request $request, Closure $next)
    {
        if (auth()->check()) {
            return $next($request);
        }

        // Redirect to the package's login route
        return redirect()->route('microsoft-sso.login');
    }
}