<?php

declare(strict_types=1);

namespace J1nn0\EncryptedS3\Support;

use J1nn0\EncryptedS3\Exceptions\InvalidConfigurationException;
use League\Flysystem\AwsS3V3\AwsS3V3Adapter;

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
            if (! is_string($key) || self::isReserved($key)) {
                continue;
            }

            if (in_array($key, AwsS3V3Adapter::AVAILABLE_OPTIONS, true)) {
                $filtered[$key] = $value;
            }
        }

        return $filtered;
    }
}
