# HashtagCMS License Client

Client SDK for the [HashtagCMS License Server](https://license.hashtagcms.org). Commercial
HashtagCMS packages (e.g. `hashtagcms-sso`) depend on this library to **enforce their license**
at runtime — it verifies a signed license key and refuses to run the package unless the key is
genuine, entitles that package, is valid for the current domain, and hasn't been revoked.

> This is the **client** half of the licensing system. The signing/issuing half (private key,
> admin panel, API) lives in the license server app and is never shipped to customers.

## Install

```bash
composer require hashtagcms/license-client
```

The service provider auto-registers. Publish the client config and (optionally) your production
public key:

```bash
php artisan vendor:publish --tag=hashtagcms-license-config
php artisan vendor:publish --tag=hashtagcms-license-key   # -> storage/app/hashtagcms/public.key
```

Set the installation's key in `.env`:

```env
HASHTAGCMS_PRO_LICENSE_KEY="eyJ0eXAi…"
HASHTAGCMS_LICENSE_SERVER=https://license.hashtagcms.org
HASHTAGCMS_LICENSE_ONLINE_CHECK=true
HASHTAGCMS_LICENSE_FAIL_OPEN=true          # keep working if the server is unreachable
# HASHTAGCMS_LICENSE_PUBLIC_KEY_PATH=/abs/path/public.key   # else the bundled key is used
```

> The bundled `resources/license/public.key` must be the **public half of the license server's
> keypair** (`php artisan license:keys:generate` on the server). Ship your production public key
> with the package; never ship the private key.

## Gate a package

In your package's service provider:

```php
use MarghoobSuleman\HashtagCmsLicense\LicenseGate;

public function boot(): void
{
    $gate = LicenseGate::for('sso');

    if ($gate->fails()) {
        logger()->warning('[hashtagcms-sso] disabled: '.$gate->reason());
        return; // do NOT register the paid feature
    }

    // Licensed — wire up routes, bindings, migrations…
    $this->loadRoutesFrom(__DIR__.'/../routes/sso.php');
}
```

One-liner / inspection:

```php
if (! LicenseGate::allows('sso')) { /* degrade / nag */ }

$gate = LicenseGate::for('sso');
$gate->passes();     // bool
$gate->reason();     // 'ok' | 'missing_license_key' | 'invalid_signature_or_expired'
                     // | 'package_not_entitled' | 'domain_not_allowed' | 'revoked_or_inactive'
$gate->payload();    // decoded license claims
```

Per-call overrides (handy for tests):

```php
LicenseGate::for('sso', [
    'license_key'  => $key,
    'online_check' => false,
    'domain'       => 'acme.com',
])->passes();
```

## What the gate checks

1. **Signature + expiry** — RS256 JWT verified against the bundled public key (offline, tamper-proof).
2. **Package entitlement** — the license's `packages` claim contains the package name (or `*`).
3. **Domain binding** — the current host matches `allowed_domains` (supports `*.example.com`).
4. **Revocation** — a cached online call to `POST /api/hashtagcms/public/license/validate` catches revoked keys.

Only when all four pass does `passes()` return `true`.

## Low-level verifier

For a pure signature check without the gate policy:

```php
use MarghoobSuleman\HashtagCmsLicense\LicenseValidator;

$payload = (new LicenseValidator($publicKeyPem))->validate($jwt); // array | false
```

## Failure policy

- `fail_open = true` (default): if the license server is unreachable, the online step does not
  block — expired/tampered/wrong-package keys are still rejected offline.
- `fail_open = false`: an unreachable server locks the package down.

Revocation reaches the client within `cache_ttl` (default 24h) after **Revoke** on the server.

## License

MIT © Marghoob Suleman
