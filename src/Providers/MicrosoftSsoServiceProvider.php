<?php

namespace DcpLibrary\MicrosoftSso\Providers;

use Illuminate\Support\ServiceProvider;
use Illuminate\Routing\Router;
use DcpLibrary\MicrosoftSso\Http\Middleware\EnsureSso;
use DcpLibrary\MicrosoftSso\Http\Middleware\EntraAuth;
use DcpLibrary\MicrosoftSso\Console\TestSsoCommand;
use DcpLibrary\MicrosoftSso\Services\JwtService;

class MicrosoftSsoServiceProvider extends ServiceProvider
{
    public function register()
    {
        // Merge package config
        $this->mergeConfigFrom(__DIR__ . '/../../config/microsoft-sso.php', 'microsoft-sso');
        
        // Register JWT service as a singleton
        $this->app->singleton(JwtService::class);
        
        // Register console commands
        if ($this->app->runningInConsole()) {
            $this->commands([
                TestSsoCommand::class,
            ]);
        }
    }

    public function boot(Router $router)
    {
        // Publish configuration
        $this->publishes([
            __DIR__ . '/../../config/microsoft-sso.php' => config_path('microsoft-sso.php'),
        ], 'microsoft-sso-config');

        // Publish views
        $this->publishes([
            __DIR__ . '/../../resources/views' => resource_path('views/vendor/microsoft-sso'),
        ], 'microsoft-sso-views');

        // Load views
        $this->loadViewsFrom(__DIR__ . '/../../resources/views', 'microsoft-sso');

        // Load routes
        $this->loadRoutesFrom(__DIR__ . '/../../routes/web.php');

        // Register middleware aliases
        $router->aliasMiddleware('sso.auto', EnsureSso::class);
        $router->aliasMiddleware('entra.auth', EntraAuth::class);
    }
}