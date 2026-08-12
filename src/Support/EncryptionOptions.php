<?php

declare(strict_types=1);

namespace J1nn0\EncryptedS3\Support;

use J1nn0\EncryptedS3\Exceptions\InvalidConfigurationException;

final class EncryptionOptions
{
    /**
     * Retained for SDK compatibility, but rejected during configuration because
     * it writes objects without key commitment.
     */
    public const COMMITMENT_POLICY_FORBID_ENCRYPT_ALLOW_DECRYPT = 'FORBID_ENCRYPT_ALLOW_DECRYPT';

    public const COMMITMENT_POLICY_REQUIRE_ENCRYPT_ALLOW_DECRYPT = 'REQUIRE_ENCRYPT_ALLOW_DECRYPT';

    public const COMMITMENT_POLICY_REQUIRE_ENCRYPT_REQUIRE_DECRYPT = 'REQUIRE_ENCRYPT_REQUIRE_DECRYPT';

    public const SECURITY_PROFILE_V3 = 'V3';

    /**
     * Retained for SDK compatibility, but rejected during configuration because
     * legacy formats do not provide key commitment.
     */
    public const SECURITY_PROFILE_V3_AND_LEGACY = 'V3_AND_LEGACY';

    /**
     * @var list<string>
     */
    private const COMMITMENT_POLICIES = [
        self::COMMITMENT_POLICY_REQUIRE_ENCRYPT_ALLOW_DECRYPT,
        self::COMMITMENT_POLICY_REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
    ];

    /**
     * @var list<string>
     */
    private const SECURITY_PROFILES = [
        self::SECURITY_PROFILE_V3,
    ];

    /**
     * @var list<string>
     */
    private const CONFIG_KEYS = [
        'commitment_policy',
        'security_profile',
        'encryption_context',
        'allow_decrypt_with_any_cmk',
    ];

    /**
     * @var list<string>
     */
    private const RESERVED_CONTEXT_KEYS = [
        'aws:x-amz-cek-alg',
        'kms_cmk_id',
    ];

    public function __construct(
        public readonly string $commitmentPolicy,
        public readonly string $securityProfile,
        /** @var array<string, string> */
        public readonly array $encryptionContext,
        public readonly bool $allowDecryptWithAnyCmk,
    ) {
        if ($commitmentPolicy === self::COMMITMENT_POLICY_FORBID_ENCRYPT_ALLOW_DECRYPT) {
            throw new InvalidConfigurationException(
                'The FORBID_ENCRYPT_ALLOW_DECRYPT commitment policy is not supported: '
                .'it writes new objects without key commitment and exposes the '
                .'GHSA-x8cp-jf6f-r4xh (CVE-2025-14761) attack surface. Use '
                .'REQUIRE_ENCRYPT_ALLOW_DECRYPT for legacy read compatibility.',
            );
        }

        if (! in_array($commitmentPolicy, self::COMMITMENT_POLICIES, true)) {
            throw new InvalidConfigurationException('The encryption commitment policy is invalid.');
        }

        if ($securityProfile === self::SECURITY_PROFILE_V3_AND_LEGACY) {
            throw new InvalidConfigurationException(
                'The V3_AND_LEGACY security profile is not supported: legacy V1/V2 '
                .'formats do not provide key commitment and expose the '
                .'GHSA-x8cp-jf6f-r4xh (CVE-2025-14761) attack surface. The AWS SDK '
                .'also emits an E_USER_WARNING for this profile, which Laravel '
                .'converts to ErrorException.',
            );
        }

        if (! in_array($securityProfile, self::SECURITY_PROFILES, true)) {
            throw new InvalidConfigurationException('The encryption security profile is invalid.');
        }

        self::validateEncryptionContext($encryptionContext);
    }

    /**
     * @param  array<mixed, mixed>  $config
     */
    public static function fromConfig(array $config): self
    {
        $config = self::assertKnownConfigKeys($config);

        $commitmentPolicy = $config['commitment_policy']
            ?? self::COMMITMENT_POLICY_REQUIRE_ENCRYPT_REQUIRE_DECRYPT;
        $securityProfile = $config['security_profile'] ?? self::SECURITY_PROFILE_V3;
        $encryptionContext = $config['encryption_context'] ?? [];
        $allowDecryptWithAnyCmk = $config['allow_decrypt_with_any_cmk'] ?? false;

        if (! is_string($commitmentPolicy) || ! is_string($securityProfile)) {
            throw new InvalidConfigurationException('The encryption options are invalid.');
        }

        if (! is_array($encryptionContext)) {
            throw new InvalidConfigurationException('The encryption context must be an associative array.');
        }

        $encryptionContext = self::validateEncryptionContext($encryptionContext);

        if (! is_bool($allowDecryptWithAnyCmk)) {
            throw new InvalidConfigurationException('The KMS CMK fallback option must be boolean.');
        }

        return new self(
            $commitmentPolicy,
            $securityProfile,
            $encryptionContext,
            $allowDecryptWithAnyCmk,
        );
    }

    /**
     * @param  array<mixed, mixed>  $config
     * @return array<string, mixed>
     */
    private static function assertKnownConfigKeys(array $config): array
    {
        $validated = [];

        foreach ($config as $key => $value) {
            if (! is_string($key) || ! in_array($key, self::CONFIG_KEYS, true)) {
                throw new InvalidConfigurationException(
                    "The encryption option {$key} is not supported.",
                );
            }

            $validated[$key] = $value;
        }

        return $validated;
    }

    /**
     * @param  array<mixed, mixed>  $context
     * @return array<string, string>
     */
    private static function validateEncryptionContext(array $context): array
    {
        if ($context !== [] && array_is_list($context)) {
            throw new InvalidConfigurationException('The encryption context must be an associative array.');
        }

        $validated = [];

        foreach ($context as $key => $value) {
            if (! is_string($key) || ! is_string($value)) {
                throw new InvalidConfigurationException('The encryption context must contain string keys and values.');
            }

            if (in_array($key, self::RESERVED_CONTEXT_KEYS, true)) {
                throw new InvalidConfigurationException('The encryption context contains a reserved key.');
            }

            $validated[$key] = $value;
        }

        return $validated;
    }
}
