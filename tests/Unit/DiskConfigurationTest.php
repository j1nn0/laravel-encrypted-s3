<?php

declare(strict_types=1);

namespace J1nn0\EncryptedS3\Tests\Unit;

use J1nn0\EncryptedS3\Exceptions\InvalidConfigurationException;
use J1nn0\EncryptedS3\Support\DiskConfiguration;
use J1nn0\EncryptedS3\Support\EncryptionOptions;
use LogicException;
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

    public function test_from_array_rejects_a_non_string_top_level_config_key(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('The disk configuration key 0 must be a string.');

        DiskConfiguration::fromArray(array_merge(['invalid'], self::validConfig()));
    }

    public function test_from_array_rejects_unknown_encryption_options(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('The encryption option encryption_contxet is not supported.');

        DiskConfiguration::fromArray(self::configWith([
            'encryption' => ['encryption_contxet' => ['tenant' => '123']],
        ]));
    }

    public function test_from_array_rejects_unknown_kms_options(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('The KMS option unknown is not supported.');

        DiskConfiguration::fromArray(self::configWith([
            'kms' => ['unknown' => 'value'],
        ]));
    }

    public function test_from_array_rejects_path_style_endpoint_in_kms_options(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('The KMS option use_path_style_endpoint is not supported.');

        DiskConfiguration::fromArray(self::configWith([
            'kms' => ['use_path_style_endpoint' => true],
        ]));
    }

    public function test_from_array_accepts_every_allowlisted_encryption_and_kms_option(): void
    {
        $configuration = DiskConfiguration::fromArray(self::configWith([
            'kms' => [
                'key_id' => 'kms-key-id',
                'region' => 'kms-region',
                'key' => 'kms-access-key',
                'secret' => 'kms-secret-key',
                'token' => 'kms-session-token',
                'credentials' => ['key' => 'credentials-key', 'secret' => 'credentials-secret'],
                'endpoint' => 'http://kms.test',
                'handler' => static function (): never {
                    throw new LogicException('not called');
                },
                'http_handler' => static function (): never {
                    throw new LogicException('not called');
                },
                'debug' => false,
                'retries' => ['max_attempts' => 1],
                'http' => ['timeout' => 10],
            ],
            'encryption' => [
                'commitment_policy' => EncryptionOptions::COMMITMENT_POLICY_REQUIRE_ENCRYPT_ALLOW_DECRYPT,
                'security_profile' => EncryptionOptions::SECURITY_PROFILE_V3,
                'encryption_context' => ['tenant' => '123'],
                'allow_decrypt_with_any_cmk' => true,
            ],
        ]));

        self::assertSame('kms-key-id', $configuration->kmsKeyId());
        self::assertSame('kms-region', $configuration->kms()['region']);
        self::assertSame(['tenant' => '123'], $configuration->encryptionOptions()->encryptionContext);
        self::assertTrue($configuration->encryptionOptions()->allowDecryptWithAnyCmk);
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

    public function test_from_array_exposes_the_validated_configuration(): void
    {
        $config = self::validConfig();
        $configuration = DiskConfiguration::fromArray($config);

        self::assertSame('bucket', $configuration->bucket());
        self::assertSame('region', $configuration->region());
        self::assertSame('root', $configuration->root());
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
        $config = array_replace_recursive(self::validConfig(), $overrides);
        $validated = [];

        foreach ($config as $key => $value) {
            if (! is_string($key)) {
                throw new LogicException('The test configuration must have string keys.');
            }

            $validated[$key] = $value;
        }

        return $validated;
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
