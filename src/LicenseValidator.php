<?php

namespace HashtagCms\LicenseClient;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Exception;

class LicenseValidator
{
    protected string $publicKey;

    public function __construct(string $publicKey = '')
    {
        $this->publicKey = $publicKey;
    }

    /**
     * Validate a license key string.
     *
     * @param string $licenseKey The JWT license string.
     * @param string|null $publicKey Optional public key (overrides constructor).
     * @return array|false Returns the decoded payload as an array if valid, false otherwise.
     */
    public function validate(string $licenseKey, ?string $publicKey = null)
    {
        $key = $publicKey ?? $this->publicKey;

        if (empty($key)) {
            // Cannot validate without a key
            return false;
        }

        try {
            // Decode the JWT
            $decoded = JWT::decode($licenseKey, new Key($key, 'RS256'));

            // Check expiry (JWT handles this mostly, but good to be explicit)
            if (isset($decoded->exp) && time() > $decoded->exp) {
                return false;
            }

            return (array) $decoded;
        } catch (Exception $e) {
            // Invalid signature, expired, or malformed
            return false;
        }
    }
}
