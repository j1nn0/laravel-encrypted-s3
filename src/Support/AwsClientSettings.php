<?php

declare(strict_types=1);

namespace J1nn0\EncryptedS3\Support;

/**
 * @internal
 */
final class AwsClientSettings
{
    public function __construct(
        private readonly DiskConfiguration $configuration,
    ) {}

    /**
     * @return array<string, mixed>
     */
    public function forS3(): array
    {
        return $this->clientConfig($this->configuration->raw(), $this->configuration->region());
    }

    /**
     * @return array<string, mixed>
     */
    public function forKms(): array
    {
        return $this->kmsClientConfig(
            $this->configuration->raw(),
            $this->configuration->kms(),
            $this->configuration->region(),
        );
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
        foreach (['endpoint', 'http_handler', 'handler', 'debug', 'retries', 'http'] as $key) {
            if (array_key_exists($key, $config)) {
                $clientConfig[$key] = $config[$key];
            }
        }

        if (array_key_exists('use_path_style_endpoint', $config)) {
            $clientConfig['use_path_style_endpoint'] = (bool) $config['use_path_style_endpoint'];
        }
    }
}
