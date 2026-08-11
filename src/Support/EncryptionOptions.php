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
     * @param  array<string, mixed>  $config
     */
    public static function fromConfig(array $config): self
    {
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

    public static function isReservedPutOption(string $key): bool
    {
        return $key === 'Metadata'
            || in_array($key, ['Body', 'Bucket', 'Key'], true)
            || str_starts_with($key, '@');
    }

    /**
     * @return array<string, mixed>
     */
    public static function validatePutOptions(mixed $options): array
    {
        if (! is_array($options)) {
            throw new InvalidConfigurationException('The S3 put options must be an array.');
        }

        foreach ($options as $key => $_value) {
            if (! is_string($key)) {
                throw new InvalidConfigurationException('The S3 put options contain an invalid key.');
            }

            if (self::isReservedPutOption($key)) {
                if ($key === 'Metadata') {
                    throw new InvalidConfigurationException('The S3 Metadata option is reserved by client-side encryption.');
                }

                throw new InvalidConfigurationException('The S3 put options contain a reserved key.');
            }
        }

        return $options;
    }

    /**
     * @param  array<mixed>  $context
     */
    private static function validateEncryptionContext(array $context): void
    {
        if ($context !== [] && array_is_list($context)) {
            throw new InvalidConfigurationException('The encryption context must be an associative array.');
        }

        foreach ($context as $key => $value) {
            if (! is_string($key) || ! is_string($value)) {
                throw new InvalidConfigurationException('The encryption context must contain string keys and values.');
            }

            if (in_array($key, self::RESERVED_CONTEXT_KEYS, true)) {
                throw new InvalidConfigurationException('The encryption context contains a reserved key.');
            }
        }
    }
}
