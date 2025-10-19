<?php

namespace DcpLibrary\MicrosoftSso\Providers;

use Illuminate\Support\ServiceProvider;
use Illuminate\Routing\Router;
use DcpLibrary\MicrosoftSso\Http\Middleware\EnsureSso;

class MicrosoftSsoServiceProvider extends ServiceProvider
{
    public function register()
    {
        // Merge package config
        $this->mergeConfigFrom(__DIR__ . '/../../config/microsoft-sso.php', 'microsoft-sso');
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

        // Register middleware alias
        $router->aliasMiddleware('sso.auto', EnsureSso::class);
    }
}