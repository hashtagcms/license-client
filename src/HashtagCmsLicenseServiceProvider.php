<?php

namespace MarghoobSuleman\HashtagCmsLicense;

use Illuminate\Support\ServiceProvider;

class HashtagCmsLicenseServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(
            dirname(__DIR__) . '/config/hashtagcms-license.php',
            'hashtagcms-license'
        );
    }

    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            // Publish the client gate config.
            $this->publishes([
                dirname(__DIR__) . '/config/hashtagcms-license.php' => config_path('hashtagcms-license.php'),
            ], 'hashtagcms-license-config');

            // Publish the bundled public key (so hosts can override it with their own).
            $this->publishes([
                dirname(__DIR__) . '/resources/license/public.key' => storage_path('app/hashtagcms/public.key'),
            ], 'hashtagcms-license-key');
        }
    }
}
