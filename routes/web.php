<?php

use Illuminate\Support\Facades\Route;
use DcpLibrary\MicrosoftSso\Http\Controllers\LoginController;
use DcpLibrary\MicrosoftSso\Http\Controllers\SsoCallbackController;

// Microsoft SSO routes
Route::prefix('microsoft-sso')->group(function () {
    Route::get('/login', [LoginController::class, 'showLogin'])->name('microsoft-sso.login');
    Route::get('/callback', [SsoCallbackController::class, 'callback'])->name('microsoft-sso.callback');
});