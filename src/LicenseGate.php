<?php

namespace HashtagCms\LicenseClient;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Throwable;

/**
 * LicenseGate
 *
 * Drop-in licensing check for HashtagCMS commercial packages (e.g. hashtagcms-sso).
 * A package unlocks only when ALL of these hold for the configured license key:
 *
 *   1. Signature + expiry are valid   (offline, tamper-proof — via LicenseValidator)
 *   2. The key entitles this package  (the `packages` claim contains it, or "*")
 *   3. This package has not expired   (offline, per-package `package_expiry` claim)
 *   4. The key is bound to this domain (offline check against allowed_domains)
 *   5. The key is not revoked/inactive (online check against the license server, cached)
 *
 * Usage in a package service provider:
 *
 *     use HashtagCms\LicenseClient\LicenseGate;
 *
 *     public function boot(): void
 *     {
 *         if (LicenseGate::for('sso')->fails()) {
 *             logger()->warning('[hashtagcms-sso] '.LicenseGate::for('sso')->reason());
 *             return; // don't register the paid feature
 *         }
 *         // ...licensed: register routes/bindings...
 *     }
 */
class LicenseGate
{
    protected string $package;

    protected array $config;

    protected ?array $payload = null;

    protected string $reason = '';

    public function __construct(string $package, array $overrides = [])
    {
        $this->package = $package;
        $this->config = array_merge($this->defaultConfig(), $this->configFromApp(), $overrides);
    }

    /**
     * Fluent factory: LicenseGate::for('sso')->passes()
     */
    public static function for(string $package, array $overrides = []): static
    {
        return new static($package, $overrides);
    }

    /**
     * One-shot boolean helper.
     */
    public static function allows(string $package, array $overrides = []): bool
    {
        return (new static($package, $overrides))->passes();
    }

    public function passes(): bool
    {
        return $this->check();
    }

    public function fails(): bool
    {
        return !$this->check();
    }

    /**
     * The decoded license payload once check() has run (or null).
     */
    public function payload(): ?array
    {
        return $this->payload;
    }

    /**
     * Machine-readable reason for the last decision ('ok', 'missing_license_key',
     * 'invalid_signature_or_expired', 'package_not_entitled', 'package_expired',
     * 'domain_not_allowed', 'revoked_or_inactive').
     */
    public function reason(): string
    {
        return $this->reason;
    }

    /**
     * Run the full gate. Returns true only if the package is licensed.
     */
    public function check(): bool
    {
        $key = $this->config['license_key'] ? trim((string) $this->config['license_key']) : '';

        if ($key === '') {
            return $this->deny('missing_license_key');
        }

        // 1) Offline: verify RS256 signature + expiry.
        $publicKey = $this->readPublicKey();
        if ($publicKey === '') {
            return $this->deny('missing_public_key');
        }

        $payload = (new LicenseValidator($publicKey))->validate($key);
        if ($payload === false) {
            return $this->deny('invalid_signature_or_expired');
        }
        $this->payload = $payload;

        // 2) Per-package entitlement.
        $packages = (array) ($payload['packages'] ?? []);
        if (!in_array($this->package, $packages, true) && !in_array('*', $packages, true)) {
            return $this->deny('package_not_entitled');
        }

        // 3) Per-package expiry (offline). A single key may carry packages that
        // expire on different dates; the server embeds a `package_expiry` map
        // (slug => unix ts) in the token. The token-level `exp` (already checked
        // in step 1) is the licence cap; this catches a package that lapsed
        // earlier while others on the same key are still valid.
        if ($this->packageExpired($payload)) {
            return $this->deny('package_expired');
        }

        // 4) Domain binding (offline).
        if (!$this->domainAllowed($payload)) {
            return $this->deny('domain_not_allowed');
        }

        // 5) Online revocation check (cached; fail-open on outage by default).
        if ($this->config['online_check'] && !$this->onlineValid($key)) {
            return $this->deny('revoked_or_inactive');
        }

        $this->reason = 'ok';

        return true;
    }

    /**
     * Read the bundled/configured public key, tolerating a missing file.
     */
    protected function readPublicKey(): string
    {
        $path = $this->config['public_key_path'] ?: (dirname(__DIR__) . '/resources/license/public.key');

        if (is_string($path) && is_file($path) && is_readable($path)) {
            return (string) file_get_contents($path);
        }

        // Allow passing the key material directly instead of a path.
        if (!empty($this->config['public_key'])) {
            return (string) $this->config['public_key'];
        }

        return '';
    }

    /**
     * Offline per-package expiry check. The token's `package_expiry` claim maps
     * package slug => effective expiry (unix ts). This package is expired only
     * when it has an explicit entry whose time has passed; a package with no
     * entry (perpetual, or governed solely by the token-level `exp`) never fails
     * here. Wildcard ('*') entitlements have no per-package entry and so are
     * governed by the token `exp` alone.
     */
    protected function packageExpired(array $payload): bool
    {
        $map = $payload['package_expiry'] ?? null;

        if (empty($map)) {
            return false;
        }

        // JWT decode yields a stdClass for the JSON object claim.
        $map = (array) $map;
        $exp = $map[$this->package] ?? null;

        if ($exp === null) {
            return false;
        }

        return time() > (int) $exp;
    }

    /**
     * Offline domain check against the license's allowed_domains (supports *.example.com).
     * When the host cannot be determined (CLI/queue) the check is lenient.
     */
    protected function domainAllowed(array $payload): bool
    {
        $allowed = $payload['allowed_domains'] ?? [];
        if (empty($allowed) || in_array('*', (array) $allowed, true)) {
            return true;
        }

        $host = $this->currentHost();
        if ($host === '') {
            return true; // cannot determine host (console) — don't hard-fail here
        }

        foreach ((array) $allowed as $pattern) {
            $pattern = strtolower(trim((string) $pattern));
            if ($pattern === '' || $pattern === $host) {
                return true;
            }
            if (str_starts_with($pattern, '*.')) {
                $root = substr($pattern, 2);
                if ($host === $root || str_ends_with($host, '.' . $root)) {
                    return true;
                }
            }
        }

        return false;
    }

    protected function currentHost(): string
    {
        if (!empty($this->config['domain'])) {
            return strtolower((string) $this->config['domain']);
        }

        try {
            $request = function_exists('request') ? request() : null;
            if ($request && method_exists($request, 'getHost')) {
                return strtolower((string) $request->getHost());
            }
        } catch (Throwable $e) {
            // ignore
        }

        try {
            $url = function_exists('config') ? config('app.url') : null;
            if ($url) {
                return strtolower((string) (parse_url($url, PHP_URL_HOST) ?: ''));
            }
        } catch (Throwable $e) {
            // ignore
        }

        return '';
    }

    /**
     * Ask the license server whether the key is still valid (catches revocation).
     * Cached for `cache_ttl` seconds. Network failures fail-open unless fail_open=false.
     */
    protected function onlineValid(string $key): bool
    {
        $cacheKey = $this->config['cache_prefix'] . ':' . $this->package . ':' . substr(hash('sha256', $key), 0, 16);

        $resolver = function () use ($key): bool {
            try {
                $url = rtrim((string) $this->config['server_url'], '/') . $this->config['validate_endpoint'];
                $response = Http::timeout((int) $this->config['http_timeout'])
                    ->acceptJson()
                    ->asForm()
                    ->post($url, [
                        'license_key' => $key,
                        'domain' => $this->currentHost(),
                        'package' => $this->package,
                    ]);

                // A definitive answer from the server is authoritative...
                if ($response->successful()) {
                    return (bool) $response->json('valid');
                }
                if ($response->status() === 403 || $response->status() === 404) {
                    return false; // revoked / not found / not authorized
                }

                // ...anything else (5xx etc.) is treated as an outage.
                return (bool) $this->config['fail_open'];
            } catch (Throwable $e) {
                return (bool) $this->config['fail_open'];
            }
        };

        try {
            return (bool) Cache::remember($cacheKey, (int) $this->config['cache_ttl'], $resolver);
        } catch (Throwable $e) {
            // Cache not available (e.g. bare CLI) — check directly.
            return $resolver();
        }
    }

    protected function deny(string $reason): bool
    {
        $this->reason = $reason;

        return false;
    }

    /**
     * Read an environment variable without relying on the framework `env()`
     * helper (which needs phpoption/phpdotenv and isn't available in a bare
     * library/test context). In a full app, published config still wins.
     */
    protected function rawEnv(string $key): ?string
    {
        $value = $_ENV[$key] ?? $_SERVER[$key] ?? getenv($key);

        return ($value === false || $value === null || $value === '') ? null : (string) $value;
    }

    protected function defaultConfig(): array
    {
        return [
            'license_key' => $this->rawEnv('HASHTAGCMS_PRO_LICENSE_KEY'),
            'public_key_path' => null,        // null => bundled resources/license/public.key
            'public_key' => null,             // or pass the PEM string directly
            'online_check' => true,
            'server_url' => 'https://hashtagcms.org',
            'validate_endpoint' => '/api/hashtagcms/public/license/validate',
            'http_timeout' => 4,
            'cache_ttl' => 60 * 60 * 24,      // 24h
            'cache_prefix' => 'hashtagcms_license',
            'fail_open' => true,              // don't take customers down if the server blips
            'domain' => null,                 // override the auto-detected host
        ];
    }

    /**
     * Pull overrides from the published `hashtagcms-license` config, if present.
     */
    protected function configFromApp(): array
    {
        if (!function_exists('config')) {
            return [];
        }

        try {
            $cfg = config('hashtagcms-license');
        } catch (Throwable $e) {
            return []; // no booted container (bare CLI) — rely on defaults/overrides
        }

        return is_array($cfg) ? array_filter($cfg, fn ($v) => $v !== null) : [];
    }
}
