<?php

declare(strict_types=1);

namespace J1nn0\EncryptedS3\Support;

use J1nn0\EncryptedS3\Exceptions\InvalidConfigurationException;

/**
 * @internal
 */
final class PutOptions
{
    public static function isReserved(string $key): bool
    {
        return $key === 'Metadata'
            || in_array($key, ['Body', 'Bucket', 'Key'], true)
            || str_starts_with($key, '@');
    }

    public static function isIncompatibleWithEncryption(string $key): bool
    {
        return in_array($key, [
            'ContentLength',
            'MetadataDirective',
            'CopySourceSSECustomerAlgorithm',
            'CopySourceSSECustomerKey',
            'CopySourceSSECustomerKeyMD5',
            'ServerSideEncryption',
            'SSEKMSKeyId',
            'SSECustomerAlgorithm',
            'SSECustomerKey',
            'SSECustomerKeyMD5',
        ], true);
    }

    public static function isSupportedByEncryption(string $key): bool
    {
        return in_array($key, [
            'ACL',
            'CacheControl',
            'ContentDisposition',
            'ContentEncoding',
            'ContentType',
            'Expires',
            'GrantFullControl',
            'GrantRead',
            'GrantReadACP',
            'GrantWriteACP',
            'RequestPayer',
            'StorageClass',
            'Tagging',
            'WebsiteRedirectLocation',
            'ChecksumAlgorithm',
        ], true);
    }

    /**
     * @return array<string, mixed>
     */
    public static function validated(mixed $options): array
    {
        if (! is_array($options)) {
            throw new InvalidConfigurationException('The S3 put options must be an array.');
        }

        foreach ($options as $key => $_value) {
            if (! is_string($key)) {
                throw new InvalidConfigurationException('The S3 put options contain an invalid key.');
            }

            if (self::isReserved($key)) {
                if ($key === 'Metadata') {
                    throw new InvalidConfigurationException('The S3 Metadata option is reserved by client-side encryption.');
                }

                throw new InvalidConfigurationException('The S3 put options contain a reserved key.');
            }

            if (self::isIncompatibleWithEncryption($key)) {
                throw new InvalidConfigurationException(
                    "The S3 put option {$key} is incompatible with client-side encryption.",
                );
            }

            if (! self::isSupportedByEncryption($key)) {
                throw new InvalidConfigurationException(
                    "The S3 put option {$key} is not supported by client-side encryption.",
                );
            }
        }

        return $options;
    }

    /**
     * @param  array<mixed, mixed>  $options
     * @return array<string, mixed>
     */
    public static function filtered(array $options): array
    {
        $filtered = [];

        foreach ($options as $key => $value) {
            if (
                ! is_string($key)
                || self::isReserved($key)
                || self::isIncompatibleWithEncryption($key)
            ) {
                continue;
            }

            if (self::isSupportedByEncryption($key)) {
                $filtered[$key] = $value;
            }
        }

        return $filtered;
    }
}
