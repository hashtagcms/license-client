<?php

/*
|--------------------------------------------------------------------------
| HashtagCMS License — Client (Gate) Configuration
|--------------------------------------------------------------------------
|
| This is the CLIENT-side config used by LicenseGate inside commercial
| packages (e.g. hashtagcms-sso) to decide whether they are licensed to run.
| It is separate from the license SERVER's issuing config.
|
| Publish with:  php artisan vendor:publish --tag=hashtagcms-license-config
|
*/

return [
    // The signed JWT license key for this installation.
    'license_key' => env('HASHTAGCMS_PRO_LICENSE_KEY'),

    // Path to the RS256 public key used to verify signatures.
    // null => use the key bundled in the package (resources/license/public.key).
    'public_key_path' => env('HASHTAGCMS_LICENSE_PUBLIC_KEY_PATH'),

    // Or provide the PEM public key inline (takes effect only if a path is not set/found).
    'public_key' => null,

    // Online revocation check against the license server.
    'online_check' => env('HASHTAGCMS_LICENSE_ONLINE_CHECK', true),
    'server_url' => env('HASHTAGCMS_LICENSE_SERVER', 'https://license.hashtagcms.org'),
    'validate_endpoint' => env('HASHTAGCMS_LICENSE_VALIDATE_ENDPOINT', '/api/hashtagcms/public/license/validate'),
    'http_timeout' => 4,

    // Cache the online result to avoid a network hit on every request.
    'cache_ttl' => env('HASHTAGCMS_LICENSE_CACHE_TTL', 60 * 60 * 24), // 24h
    'cache_prefix' => 'hashtagcms_license',

    // If the license server is unreachable, keep working (true) or lock down (false).
    'fail_open' => env('HASHTAGCMS_LICENSE_FAIL_OPEN', true),

    // Override the auto-detected host used for domain-binding checks.
    'domain' => env('HASHTAGCMS_LICENSE_DOMAIN'),
];
