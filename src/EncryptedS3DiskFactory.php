<?php

declare(strict_types=1);

namespace J1nn0\EncryptedS3;

use Aws\Crypto\KmsMaterialsProviderV3;
use Aws\Kms\KmsClient;
use Aws\S3\Crypto\S3EncryptionClientV3;
use Aws\S3\S3Client;
use J1nn0\EncryptedS3\Exceptions\InvalidConfigurationException;
use J1nn0\EncryptedS3\Filesystem\EncryptedS3Filesystem;
use J1nn0\EncryptedS3\Flysystem\EncryptedS3Adapter;
use J1nn0\EncryptedS3\Support\EncryptedS3Arguments;
use J1nn0\EncryptedS3\Support\EncryptionOptions;
use J1nn0\EncryptedS3\Support\ObjectLocation;
use J1nn0\EncryptedS3\Support\PutOptions;
use League\Flysystem\AwsS3V3\AwsS3V3Adapter;
use League\Flysystem\AwsS3V3\PortableVisibilityConverter;
use League\Flysystem\Filesystem;
use League\MimeTypeDetection\FinfoMimeTypeDetector;

final class EncryptedS3DiskFactory
{
    /**
     * @param  array<string, mixed>  $config
     */
    public function make(array $config): EncryptedS3Filesystem
    {
        $bucket = $this->requiredString($config, 'bucket', 'The encrypted S3 bucket is required.');
        $region = $this->requiredString($config, 'region', 'The encrypted S3 region is required.');
        $encryptionConfig = $config['encryption'] ?? [];
        $kmsConfig = $config['kms'] ?? [];

        if (! is_array($encryptionConfig)) {
            throw new InvalidConfigurationException('The encryption configuration must be an array.');
        }

        if (! is_array($kmsConfig)) {
            throw new InvalidConfigurationException('The KMS configuration must be an array.');
        }

        $kmsKeyId = $kmsConfig['key_id'] ?? null;

        if (! is_string($kmsKeyId) || trim($kmsKeyId) === '') {
            throw new InvalidConfigurationException('The KMS key ID is required for client-side encryption.');
        }

        $encryptionOptions = EncryptionOptions::fromConfig($encryptionConfig);
        $putOptions = PutOptions::validated($config['options'] ?? []);
        $visibility = new PortableVisibilityConverter;
        $mimeTypeDetector = new FinfoMimeTypeDetector;
        $root = is_string($config['root'] ?? '') ? $config['root'] : '';
        $location = new ObjectLocation($bucket, $root);
        $s3Client = new S3Client($this->clientConfig($config, $region));
        $kmsClient = new KmsClient($this->kmsClientConfig($config, $kmsConfig, $region));
        $materialsProvider = new KmsMaterialsProviderV3($kmsClient, $kmsKeyId);
        $encryptionClient = new S3EncryptionClientV3($s3Client);
        $inner = new AwsS3V3Adapter(
            $s3Client,
            $location->bucket(),
            $location->root(),
            $visibility,
            $mimeTypeDetector,
        );

        if (! array_key_exists('ACL', $putOptions)) {
            $putOptions['ACL'] = $visibility->visibilityToAcl(
                is_string($config['visibility'] ?? null) && $config['visibility'] !== ''
                    ? $config['visibility']
                    : 'private'
            );
        }

        $arguments = new EncryptedS3Arguments(
            $materialsProvider,
            $location,
            $mimeTypeDetector,
            $visibility,
            $encryptionOptions,
            $putOptions,
        );
        $adapter = new EncryptedS3Adapter(
            $encryptionClient,
            $inner,
            $arguments,
        );
        $filesystem = new Filesystem($adapter, $config);

        return new EncryptedS3Filesystem($filesystem, $adapter, $config);
    }

    /**
     * @param  array<string, mixed>  $config
     * @return array<string, mixed>
     */
    private function clientConfig(array $config, string $region): array
    {
        $clientConfig = [
            'version' => 'latest',
            'region' => $region,
        ];

        $this->addCredentials($clientConfig, $config);
        $this->addOptionalClientSettings($clientConfig, $config);

        return $clientConfig;
    }

    /**
     * @param  array<string, mixed>  $rootConfig
     * @param  array<string, mixed>  $kmsConfig
     * @return array<string, mixed>
     */
    private function kmsClientConfig(array $rootConfig, array $kmsConfig, string $region): array
    {
        $clientConfig = [
            'version' => 'latest',
            'region' => is_string($kmsConfig['region'] ?? null) && $kmsConfig['region'] !== ''
                ? $kmsConfig['region']
                : $region,
        ];

        $this->addCredentials($clientConfig, $kmsConfig, $rootConfig);
        $this->addOptionalClientSettings($clientConfig, $kmsConfig);

        return $clientConfig;
    }

    /**
     * @param  array<string, mixed>  $clientConfig
     * @param  array<string, mixed>  $config
     * @param  array<string, mixed>|null  $fallback
     */
    private function addCredentials(array &$clientConfig, array $config, ?array $fallback = null): void
    {
        if (isset($config['credentials']) && is_array($config['credentials'])) {
            $clientConfig['credentials'] = $config['credentials'];

            return;
        }

        $key = $config['key'] ?? $fallback['key'] ?? null;
        $secret = $config['secret'] ?? $fallback['secret'] ?? null;
        $token = $config['token'] ?? $fallback['token'] ?? null;

        if (is_string($key) && is_string($secret) && $key !== '' && $secret !== '') {
            $clientConfig['credentials'] = array_filter([
                'key' => $key,
                'secret' => $secret,
                'token' => $token,
            ], static fn ($value): bool => $value !== null);
        }
    }

    /**
     * @param  array<string, mixed>  $clientConfig
     * @param  array<string, mixed>  $config
     */
    private function addOptionalClientSettings(array &$clientConfig, array $config): void
    {
        foreach (['endpoint', 'http_handler', 'handler', 'debug'] as $key) {
            if (array_key_exists($key, $config)) {
                $clientConfig[$key] = $config[$key];
            }
        }

        if (array_key_exists('use_path_style_endpoint', $config)) {
            $clientConfig['use_path_style_endpoint'] = (bool) $config['use_path_style_endpoint'];
        }
    }

    /**
     * @param  array<string, mixed>  $config
     */
    private function requiredString(array $config, string $key, string $message): string
    {
        $value = $config[$key] ?? null;

        if (! is_string($value) || trim($value) === '') {
            throw new InvalidConfigurationException($message);
        }

        return $value;
    }
}
