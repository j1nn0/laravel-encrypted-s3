<?php

declare(strict_types=1);

namespace J1nn0\EncryptedS3\Tests\Unit;

use J1nn0\EncryptedS3\Exceptions\InvalidConfigurationException;
use J1nn0\EncryptedS3\Support\DiskConfiguration;
use J1nn0\EncryptedS3\Support\EncryptionOptions;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class DiskConfigurationTest extends TestCase
{
    /**
     * @return iterable<string, array{array<string, mixed>, string}>
     */
    public static function invalidBucketProvider(): iterable
    {
        $missing = self::validConfig();
        unset($missing['bucket']);

        yield 'missing bucket' => [$missing, 'The encrypted S3 bucket is required.'];
        yield 'empty bucket' => [self::configWith(['bucket' => '']), 'The encrypted S3 bucket is required.'];
        yield 'non-string bucket' => [self::configWith(['bucket' => 123]), 'The encrypted S3 bucket is required.'];
    }

    /**
     * @return iterable<string, array{array<string, mixed>, string}>
     */
    public static function invalidRegionProvider(): iterable
    {
        $missing = self::validConfig();
        unset($missing['region']);

        yield 'missing region' => [$missing, 'The encrypted S3 region is required.'];
        yield 'empty region' => [self::configWith(['region' => '']), 'The encrypted S3 region is required.'];
        yield 'non-string region' => [self::configWith(['region' => 123]), 'The encrypted S3 region is required.'];
    }

    /**
     * @return iterable<string, array{array<string, mixed>, string}>
     */
    public static function invalidKmsKeyIdProvider(): iterable
    {
        $missing = self::validConfig();
        $missing['kms'] = [];

        yield 'missing key id' => [$missing, 'The KMS key ID is required for client-side encryption.'];
        yield 'empty key id' => [self::configWith(['kms' => ['key_id' => '']]), 'The KMS key ID is required for client-side encryption.'];
        yield 'non-string key id' => [self::configWith(['kms' => ['key_id' => 123]]), 'The KMS key ID is required for client-side encryption.'];
    }

    /**
     * @param  array<string, mixed>  $config
     */
    #[DataProvider('invalidBucketProvider')]
    public function test_from_array_rejects_invalid_bucket(array $config, string $message): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage($message);

        DiskConfiguration::fromArray($config);
    }

    /**
     * @param  array<string, mixed>  $config
     */
    #[DataProvider('invalidRegionProvider')]
    public function test_from_array_rejects_invalid_region(array $config, string $message): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage($message);

        DiskConfiguration::fromArray($config);
    }

    public function test_from_array_rejects_non_array_encryption_configuration(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('The encryption configuration must be an array.');

        DiskConfiguration::fromArray(self::configWith(['encryption' => 'invalid']));
    }

    public function test_from_array_rejects_non_array_kms_configuration(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('The KMS configuration must be an array.');

        DiskConfiguration::fromArray(self::configWith(['kms' => 'invalid']));
    }

    /**
     * @param  array<string, mixed>  $config
     */
    #[DataProvider('invalidKmsKeyIdProvider')]
    public function test_from_array_rejects_invalid_kms_key_id(array $config, string $message): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage($message);

        DiskConfiguration::fromArray($config);
    }

    public function test_from_array_defaults_missing_root_to_an_empty_string(): void
    {
        $config = self::validConfig();
        unset($config['root']);

        self::assertSame('', DiskConfiguration::fromArray($config)->root());
    }

    public function test_from_array_defaults_non_string_root_to_an_empty_string(): void
    {
        self::assertSame('', DiskConfiguration::fromArray(self::configWith(['root' => 123]))->root());
    }

    public function test_from_array_defaults_missing_or_invalid_visibility_to_private(): void
    {
        $config = self::validConfig();
        unset($config['visibility']);

        self::assertSame('private', DiskConfiguration::fromArray($config)->visibility());
        self::assertSame('private', DiskConfiguration::fromArray(self::configWith(['visibility' => '']))->visibility());
        self::assertSame('private', DiskConfiguration::fromArray(self::configWith(['visibility' => 123]))->visibility());
    }

    public function test_from_array_exposes_the_validated_configuration(): void
    {
        $config = self::validConfig();
        $configuration = DiskConfiguration::fromArray($config);

        self::assertSame('bucket', $configuration->bucket());
        self::assertSame('region', $configuration->region());
        self::assertSame('root', $configuration->root());
        self::assertSame('public', $configuration->visibility());
        self::assertSame('kms-key-id', $configuration->kmsKeyId());
        self::assertSame(
            EncryptionOptions::COMMITMENT_POLICY_REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
            $configuration->encryptionOptions()->commitmentPolicy,
        );
        self::assertSame(['CacheControl' => 'max-age=60'], $configuration->putOptions());
        self::assertSame(['key_id' => 'kms-key-id', 'region' => 'kms-region'], $configuration->kms());
        self::assertSame($config, $configuration->raw());
    }

    public function test_from_array_rejects_reserved_put_options_during_validation(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('The S3 Metadata option is reserved by client-side encryption.');

        DiskConfiguration::fromArray(self::configWith([
            'options' => ['Metadata' => ['unsafe' => 'value']],
        ]));
    }

    /**
     * @param  array<string, mixed>  $overrides
     * @return array<string, mixed>
     */
    private static function configWith(array $overrides): array
    {
        return array_replace_recursive(self::validConfig(), $overrides);
    }

    /**
     * @return array<string, mixed>
     */
    private static function validConfig(): array
    {
        return [
            'bucket' => 'bucket',
            'region' => 'region',
            'root' => 'root',
            'visibility' => 'public',
            'options' => ['CacheControl' => 'max-age=60'],
            'kms' => [
                'key_id' => 'kms-key-id',
                'region' => 'kms-region',
            ],
            'encryption' => [
                'commitment_policy' => EncryptionOptions::COMMITMENT_POLICY_REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
                'security_profile' => EncryptionOptions::SECURITY_PROFILE_V3,
                'encryption_context' => [],
                'allow_decrypt_with_any_cmk' => false,
            ],
        ];
    }
}
