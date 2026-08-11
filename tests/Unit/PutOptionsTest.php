<?php

declare(strict_types=1);

namespace J1nn0\EncryptedS3\Tests\Unit;

use J1nn0\EncryptedS3\Exceptions\InvalidConfigurationException;
use J1nn0\EncryptedS3\Support\PutOptions;
use League\Flysystem\AwsS3V3\AwsS3V3Adapter;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class PutOptionsTest extends TestCase
{
    /**
     * @return iterable<string, array{string, bool}>
     */
    public static function reservedOptionProvider(): iterable
    {
        yield 'metadata' => ['Metadata', true];
        yield 'body' => ['Body', true];
        yield 'bucket' => ['Bucket', true];
        yield 'key' => ['Key', true];
        yield 'internal option' => ['@MetadataStrategy', true];
        yield 'content length' => ['ContentLength', false];
        yield 'metadata directive' => ['MetadataDirective', false];
        yield 'copy source SSE customer algorithm' => ['CopySourceSSECustomerAlgorithm', false];
        yield 'copy source SSE customer key' => ['CopySourceSSECustomerKey', false];
        yield 'copy source SSE customer key MD5' => ['CopySourceSSECustomerKeyMD5', false];
        yield 'server-side encryption' => ['ServerSideEncryption', false];
        yield 'SSE KMS key ID' => ['SSEKMSKeyId', false];
        yield 'SSE customer algorithm' => ['SSECustomerAlgorithm', false];
        yield 'SSE customer key' => ['SSECustomerKey', false];
        yield 'SSE customer key MD5' => ['SSECustomerKeyMD5', false];
        yield 'cache control' => ['CacheControl', false];
        yield 'acl' => ['ACL', false];
        yield 'storage class' => ['StorageClass', false];
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function incompatibleOptionProvider(): iterable
    {
        yield 'content length' => ['ContentLength'];
        yield 'metadata directive' => ['MetadataDirective'];
        yield 'copy source SSE customer algorithm' => ['CopySourceSSECustomerAlgorithm'];
        yield 'copy source SSE customer key' => ['CopySourceSSECustomerKey'];
        yield 'copy source SSE customer key MD5' => ['CopySourceSSECustomerKeyMD5'];
        yield 'server-side encryption' => ['ServerSideEncryption'];
        yield 'SSE KMS key ID' => ['SSEKMSKeyId'];
        yield 'SSE customer algorithm' => ['SSECustomerAlgorithm'];
        yield 'SSE customer key' => ['SSECustomerKey'];
        yield 'SSE customer key MD5' => ['SSECustomerKeyMD5'];
    }

    #[DataProvider('reservedOptionProvider')]
    public function test_is_reserved_identifies_owned_and_unowned_options(string $key, bool $expected): void
    {
        self::assertSame($expected, PutOptions::isReserved($key));
    }

    #[DataProvider('incompatibleOptionProvider')]
    public function test_is_incompatible_with_encryption_identifies_incompatible_options(string $key): void
    {
        self::assertTrue(PutOptions::isIncompatibleWithEncryption($key));
    }

    public function test_each_upstream_put_option_has_exactly_one_package_classification(): void
    {
        foreach (AwsS3V3Adapter::AVAILABLE_OPTIONS as $option) {
            $classifications = [
                'supported' => PutOptions::isSupportedByEncryption($option),
                'reserved' => PutOptions::isReserved($option),
                'incompatible' => PutOptions::isIncompatibleWithEncryption($option),
            ];

            self::assertSame(
                1,
                count(array_filter($classifications)),
                "Put option {$option} must have exactly one package classification.",
            );
        }
    }

    public function test_validated_rejects_non_array_options(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('The S3 put options must be an array.');

        PutOptions::validated('invalid');
    }

    public function test_validated_rejects_non_string_keys(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('The S3 put options contain an invalid key.');

        PutOptions::validated([123 => 'invalid']);
    }

    public function test_validated_rejects_reserved_keys(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('The S3 put options contain a reserved key.');

        PutOptions::validated(['Body' => 'invalid']);
    }

    public function test_validated_uses_a_specific_metadata_message(): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('The S3 Metadata option is reserved by client-side encryption.');

        PutOptions::validated(['Metadata' => ['invalid' => 'value']]);
    }

    #[DataProvider('incompatibleOptionProvider')]
    public function test_validated_rejects_options_incompatible_with_encryption(string $key): void
    {
        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage("The S3 put option {$key} is incompatible with client-side encryption.");

        PutOptions::validated([$key => 'invalid']);
    }

    public function test_validated_returns_valid_options_unchanged(): void
    {
        $options = [
            'CacheControl' => 'max-age=60',
            'ACL' => 'private',
            'StorageClass' => 'STANDARD',
        ];

        self::assertSame($options, PutOptions::validated($options));
    }

    public function test_filtered_removes_reserved_options(): void
    {
        $options = [
            'Metadata' => ['unsafe' => 'value'],
            'Body' => 'unsafe',
            'Bucket' => 'unsafe',
            'Key' => 'unsafe',
            '@MetadataStrategy' => 'unsafe',
            'CacheControl' => 'max-age=60',
        ];

        self::assertSame(['CacheControl' => 'max-age=60'], PutOptions::filtered($options));
    }

    #[DataProvider('incompatibleOptionProvider')]
    public function test_filtered_removes_options_incompatible_with_encryption(string $key): void
    {
        self::assertSame(
            ['CacheControl' => 'max-age=60'],
            PutOptions::filtered([
                $key => 'unsafe',
                'CacheControl' => 'max-age=60',
            ]),
        );
    }

    public function test_filtered_removes_options_outside_the_s3_allowlist(): void
    {
        self::assertSame(
            ['CacheControl' => 'max-age=60'],
            PutOptions::filtered([
                'CacheControl' => 'max-age=60',
                'custom-option' => 'unsafe',
            ]),
        );
    }

    public function test_filtered_passes_allowlisted_options(): void
    {
        $options = [
            'CacheControl' => 'max-age=60',
            'ACL' => 'private',
            'StorageClass' => 'STANDARD',
        ];

        self::assertSame($options, PutOptions::filtered($options));
    }

    public function test_filtered_removes_non_string_keys(): void
    {
        self::assertSame(
            ['ACL' => 'private'],
            PutOptions::filtered([
                123 => 'invalid',
                'ACL' => 'private',
            ]),
        );
    }

    public function test_filtered_drops_all_disk_config_keys_from_filesystem_options(): void
    {
        $diskConfig = [
            'key' => 'access-key',
            'secret' => 'secret',
            'region' => 'us-east-1',
            'bucket' => 'bucket',
            'endpoint' => 'http://localhost',
            'root' => 'root',
            'visibility' => 'private',
            'throw' => true,
            'options' => ['CacheControl' => 'max-age=60'],
            'handler' => 'handler',
            'kms' => ['key_id' => 'key-id'],
            'encryption' => ['security_profile' => 'V3'],
        ];

        $filtered = PutOptions::filtered($diskConfig);

        foreach (array_keys($diskConfig) as $key) {
            self::assertArrayNotHasKey($key, $filtered);
        }
    }
}
