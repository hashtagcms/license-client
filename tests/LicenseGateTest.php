<?php

namespace HashtagCms\LicenseClient\Tests;

use Firebase\JWT\JWT;
use HashtagCms\LicenseClient\LicenseGate;
use HashtagCms\LicenseClient\LicenseValidator;
use PHPUnit\Framework\TestCase;

/**
 * Self-contained: generates its own RSA keypair so the tests never depend on
 * the license server or a live network (online_check is disabled throughout).
 */
class LicenseGateTest extends TestCase
{
    private string $privateKey;

    private string $publicKeyPath;

    protected function setUp(): void
    {
        $res = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);
        openssl_pkey_export($res, $priv);
        $this->privateKey = $priv;

        $details = openssl_pkey_get_details($res);
        $this->publicKeyPath = tempnam(sys_get_temp_dir(), 'hcms_pub_');
        file_put_contents($this->publicKeyPath, $details['key']);
    }

    protected function tearDown(): void
    {
        @unlink($this->publicKeyPath);
    }

    private function sign(array $payload): string
    {
        $payload += ['iss' => 'test', 'iat' => time()];

        return JWT::encode($payload, $this->privateKey, 'RS256');
    }

    private function gate(string $package, string $key, array $extra = []): LicenseGate
    {
        return LicenseGate::for($package, array_merge([
            'license_key' => $key,
            'public_key_path' => $this->publicKeyPath,
            'online_check' => false,
        ], $extra));
    }

    public function test_valid_entitled_and_domain_bound_passes(): void
    {
        $key = $this->sign([
            'tier' => 'enterprise',
            'packages' => ['sso', 'payments'],
            'allowed_domains' => ['acme.com'],
            'domain' => 'acme.com',
            'exp' => time() + 3600,
        ]);

        $gate = $this->gate('sso', $key, ['domain' => 'acme.com']);
        $this->assertTrue($gate->passes());
        $this->assertSame('ok', $gate->reason());
    }

    public function test_wildcard_domain_passes(): void
    {
        $key = $this->sign([
            'packages' => ['sso'],
            'allowed_domains' => ['*.acme.com'],
            'exp' => time() + 3600,
        ]);

        $this->assertTrue($this->gate('sso', $key, ['domain' => 'app.acme.com'])->passes());
    }

    public function test_wrong_domain_fails(): void
    {
        $key = $this->sign([
            'packages' => ['sso'],
            'allowed_domains' => ['acme.com'],
            'exp' => time() + 3600,
        ]);

        $gate = $this->gate('sso', $key, ['domain' => 'evil.com']);
        $this->assertFalse($gate->passes());
        $this->assertSame('domain_not_allowed', $gate->reason());
    }

    public function test_package_not_entitled_fails(): void
    {
        $key = $this->sign(['packages' => ['extended'], 'exp' => time() + 3600]);

        $gate = $this->gate('sso', $key, ['domain' => 'acme.com']);
        $this->assertFalse($gate->passes());
        $this->assertSame('package_not_entitled', $gate->reason());
    }

    public function test_wildcard_entitlement_passes(): void
    {
        $key = $this->sign(['packages' => ['*'], 'exp' => time() + 3600]);

        $this->assertTrue($this->gate('sso', $key)->passes());
    }

    public function test_expired_fails(): void
    {
        $key = $this->sign(['packages' => ['sso'], 'exp' => time() - 10]);

        $gate = $this->gate('sso', $key);
        $this->assertFalse($gate->passes());
        $this->assertSame('invalid_signature_or_expired', $gate->reason());
    }

    public function test_tampered_key_fails(): void
    {
        $key = $this->sign(['packages' => ['sso'], 'exp' => time() + 3600]);
        $tampered = substr($key, 0, -6) . 'AAAAAA';

        $gate = $this->gate('sso', $tampered);
        $this->assertFalse($gate->passes());
        $this->assertSame('invalid_signature_or_expired', $gate->reason());
    }

    public function test_empty_key_fails(): void
    {
        $gate = $this->gate('sso', '');
        $this->assertFalse($gate->passes());
        $this->assertSame('missing_license_key', $gate->reason());
    }

    public function test_no_domain_binding_allows_any_host(): void
    {
        $key = $this->sign(['packages' => ['sso'], 'exp' => time() + 3600]); // no allowed_domains

        $this->assertTrue($this->gate('sso', $key, ['domain' => 'anything.example'])->passes());
    }

    public function test_package_expired_fails_while_others_on_same_key_pass(): void
    {
        $key = $this->sign([
            'packages' => ['commerce', 'booking_engine'],
            'exp' => time() + 86400, // licence cap still valid
            'package_expiry' => [
                'commerce' => time() - 10,          // this package lapsed
                'booking_engine' => time() + 3600,  // still valid
            ],
        ]);

        $commerce = $this->gate('commerce', $key);
        $this->assertFalse($commerce->passes());
        $this->assertSame('package_expired', $commerce->reason());

        $booking = $this->gate('booking_engine', $key);
        $this->assertTrue($booking->passes());
        $this->assertSame('ok', $booking->reason());
    }

    public function test_package_without_expiry_entry_is_governed_by_token_exp(): void
    {
        $key = $this->sign([
            'packages' => ['sso', 'commerce'],
            'exp' => time() + 3600,
            'package_expiry' => ['commerce' => time() - 10], // only commerce carries a date
        ]);

        // sso has no per-package entry → not expired at this step
        $this->assertTrue($this->gate('sso', $key)->passes());
        // commerce lapsed
        $commerce = $this->gate('commerce', $key);
        $this->assertTrue($commerce->fails());
        $this->assertSame('package_expired', $commerce->reason());
    }

    public function test_wildcard_entitlement_unaffected_by_unrelated_package_expiry(): void
    {
        $key = $this->sign([
            'packages' => ['*'],
            'exp' => time() + 3600,
            'package_expiry' => ['commerce' => time() - 10],
        ]);

        // '*' grants sso; sso has no entry in the map, so it stays valid
        $this->assertTrue($this->gate('sso', $key)->passes());
    }

    public function test_validator_returns_payload_for_valid_key(): void
    {
        $key = $this->sign(['packages' => ['sso'], 'tier' => 'enterprise', 'exp' => time() + 3600]);
        $payload = (new LicenseValidator(file_get_contents($this->publicKeyPath)))->validate($key);

        $this->assertIsArray($payload);
        $this->assertSame('enterprise', $payload['tier']);
    }
}
