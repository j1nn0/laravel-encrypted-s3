<?php

declare(strict_types=1);

namespace J1nn0\EncryptedS3\Support;

use J1nn0\EncryptedS3\Exceptions\InvalidConfigurationException;

/**
 * @internal
 */
final class DiskConfiguration
{
    /**
     * @var list<string>
     */
    private const KMS_CONFIG_KEYS = [
        'key_id',
        'region',
        'key',
        'secret',
        'token',
        'credentials',
        'endpoint',
        'handler',
        'http_handler',
        'debug',
        'retries',
        'http',
    ];

    /**
     * @param  array<string, mixed>  $kms
     * @param  array<string, mixed>  $putOptions
     * @param  array<string, mixed>  $raw
     */
    private function __construct(
        private readonly string $bucket,
        private readonly string $region,
        private readonly string $root,
        private readonly string $kmsKeyId,
        private readonly EncryptionOptions $encryptionOptions,
        private readonly array $putOptions,
        private readonly array $kms,
        private readonly array $raw,
    ) {}

    /**
     * @param  array<string, mixed>  $config
     */
    public static function fromArray(array $config): self
    {
        $bucket = self::requiredString($config, 'bucket', 'The encrypted S3 bucket is required.');
        $region = self::requiredString($config, 'region', 'The encrypted S3 region is required.');
        $encryptionConfig = $config['encryption'] ?? [];
        $kmsConfig = $config['kms'] ?? [];

        if (! is_array($encryptionConfig)) {
            throw new InvalidConfigurationException('The encryption configuration must be an array.');
        }

        if (! is_array($kmsConfig)) {
            throw new InvalidConfigurationException('The KMS configuration must be an array.');
        }

        self::assertKnownKmsConfigKeys($kmsConfig);

        $kmsKeyId = $kmsConfig['key_id'] ?? null;

        if (! is_string($kmsKeyId) || trim($kmsKeyId) === '') {
            throw new InvalidConfigurationException('The KMS key ID is required for client-side encryption.');
        }

        $encryptionOptions = EncryptionOptions::fromConfig($encryptionConfig);
        $putOptions = PutOptions::validated($config['options'] ?? []);
        $root = is_string($config['root'] ?? null) ? $config['root'] : '';

        return new self(
            $bucket,
            $region,
            $root,
            $kmsKeyId,
            $encryptionOptions,
            $putOptions,
            $kmsConfig,
            $config,
        );
    }

    /**
     * @param  array<mixed, mixed>  $config
     */
    private static function assertKnownKmsConfigKeys(array $config): void
    {
        foreach (array_keys($config) as $key) {
            if (! is_string($key) || ! in_array($key, self::KMS_CONFIG_KEYS, true)) {
                throw new InvalidConfigurationException(
                    "The KMS option {$key} is not supported.",
                );
            }
        }
    }

    public function bucket(): string
    {
        return $this->bucket;
    }

    public function region(): string
    {
        return $this->region;
    }

    public function root(): string
    {
        return $this->root;
    }

    public function kmsKeyId(): string
    {
        return $this->kmsKeyId;
    }

    public function encryptionOptions(): EncryptionOptions
    {
        return $this->encryptionOptions;
    }

    /**
     * @return array<string, mixed>
     */
    public function putOptions(): array
    {
        return $this->putOptions;
    }

    /**
     * @return array<string, mixed>
     */
    public function kms(): array
    {
        return $this->kms;
    }

    /**
     * @return array<string, mixed>
     */
    public function raw(): array
    {
        return $this->raw;
    }

    /**
     * @param  array<string, mixed>  $config
     */
    private static function requiredString(array $config, string $key, string $message): string
    {
        $value = $config[$key] ?? null;

        if (! is_string($value) || trim($value) === '') {
            throw new InvalidConfigurationException($message);
        }

        return $value;
    }
}
