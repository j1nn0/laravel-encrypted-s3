<?php

declare(strict_types=1);

namespace J1nn0\EncryptedS3\Tests\Unit;

use J1nn0\EncryptedS3\Exceptions\InvalidConfigurationException;
use J1nn0\EncryptedS3\Support\PutOptions;
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
        yield 'cache control' => ['CacheControl', false];
        yield 'acl' => ['ACL', false];
        yield 'storage class' => ['StorageClass', false];
    }

    #[DataProvider('reservedOptionProvider')]
    public function test_is_reserved_identifies_owned_and_unowned_options(string $key, bool $expected): void
    {
        self::assertSame($expected, PutOptions::isReserved($key));
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
