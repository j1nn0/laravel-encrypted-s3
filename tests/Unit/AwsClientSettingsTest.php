<?php

declare(strict_types=1);

namespace J1nn0\EncryptedS3\Tests\Unit;

use J1nn0\EncryptedS3\Support\AwsClientSettings;
use J1nn0\EncryptedS3\Support\DiskConfiguration;
use PHPUnit\Framework\TestCase;
use stdClass;

final class AwsClientSettingsTest extends TestCase
{
    public function test_for_s3_contains_version_region_and_disk_credentials(): void
    {
        $settings = $this->settings()->forS3();

        self::assertSame('latest', $settings['version']);
        self::assertSame('disk-region', $settings['region']);
        self::assertSame([
            'key' => 'disk-key',
            'secret' => 'disk-secret',
        ], $settings['credentials']);
    }

    public function test_for_kms_uses_the_configured_kms_region(): void
    {
        $settings = $this->settings(['kms' => ['region' => 'kms-region']])->forKms();

        self::assertSame('kms-region', $settings['region']);
    }

    public function test_for_kms_falls_back_to_the_disk_region_when_kms_region_is_missing(): void
    {
        $settings = $this->settings()->forKms();

        self::assertSame('disk-region', $settings['region']);
    }

    public function test_for_kms_falls_back_to_the_disk_region_when_kms_region_is_empty(): void
    {
        $settings = $this->settings(['kms' => ['region' => '']])->forKms();

        self::assertSame('disk-region', $settings['region']);
    }

    public function test_for_kms_falls_back_to_disk_credentials_without_a_token(): void
    {
        $credentials = $this->settings()->forKms()['credentials'];

        self::assertSame([
            'key' => 'disk-key',
            'secret' => 'disk-secret',
        ], $credentials);
        self::assertArrayNotHasKey('token', $credentials);
    }

    public function test_for_kms_prefers_kms_key_and_secret_over_disk_credentials(): void
    {
        $credentials = $this->settings([
            'kms' => [
                'key' => 'kms-key',
                'secret' => 'kms-secret',
            ],
        ])->forKms()['credentials'];

        self::assertSame([
            'key' => 'kms-key',
            'secret' => 'kms-secret',
        ], $credentials);
    }

    public function test_for_kms_prefers_kms_credentials_over_kms_key_and_secret(): void
    {
        $credentials = $this->settings([
            'kms' => [
                'key' => 'kms-key',
                'secret' => 'kms-secret',
                'credentials' => [
                    'key' => 'credentials-key',
                    'secret' => 'credentials-secret',
                    'token' => 'credentials-token',
                ],
            ],
        ])->forKms()['credentials'];

        self::assertSame([
            'key' => 'credentials-key',
            'secret' => 'credentials-secret',
            'token' => 'credentials-token',
        ], $credentials);
    }

    public function test_for_s3_passes_optional_settings_and_casts_path_style_to_bool(): void
    {
        $httpHandler = new stdClass;
        $handler = new stdClass;
        $settings = $this->settings([
            'endpoint' => 'http://s3.test',
            'http_handler' => $httpHandler,
            'handler' => $handler,
            'debug' => true,
            'use_path_style_endpoint' => 1,
            'retries' => ['mode' => 'standard', 'max_attempts' => 5],
            'http' => ['timeout' => 10, 'proxy' => 'http://proxy.test'],
        ])->forS3();

        self::assertSame('http://s3.test', $settings['endpoint']);
        self::assertSame($httpHandler, $settings['http_handler']);
        self::assertSame($handler, $settings['handler']);
        self::assertTrue($settings['debug']);
        self::assertTrue($settings['use_path_style_endpoint']);
        self::assertSame(['mode' => 'standard', 'max_attempts' => 5], $settings['retries']);
        self::assertSame(['timeout' => 10, 'proxy' => 'http://proxy.test'], $settings['http']);
    }

    public function test_optional_settings_are_absent_when_the_disk_does_not_set_them(): void
    {
        $settings = $this->settings([])->forS3();

        foreach (['endpoint', 'http_handler', 'handler', 'debug', 'retries', 'http', 'use_path_style_endpoint'] as $key) {
            self::assertArrayNotHasKey($key, $settings);
        }
    }

    public function test_for_kms_ignores_the_s3_only_path_style_setting(): void
    {
        $httpHandler = new stdClass;
        $handler = new stdClass;
        $settings = $this->settings([
            'kms' => [
                'endpoint' => 'http://kms.test',
                'http_handler' => $httpHandler,
                'handler' => $handler,
                'debug' => true,
                'use_path_style_endpoint' => 0,
                'retries' => 2,
                'http' => ['timeout' => 3],
            ],
        ])->forKms();

        self::assertSame('http://kms.test', $settings['endpoint']);
        self::assertSame($httpHandler, $settings['http_handler']);
        self::assertSame($handler, $settings['handler']);
        self::assertTrue($settings['debug']);
        self::assertArrayNotHasKey('use_path_style_endpoint', $settings);
        self::assertSame(2, $settings['retries']);
        self::assertSame(['timeout' => 3], $settings['http']);
    }

    public function test_kms_optional_settings_are_not_inherited_from_the_disk(): void
    {
        $settings = $this->settings([
            'retries' => 9,
            'http' => ['timeout' => 99],
            'endpoint' => 'http://s3.test',
        ])->forKms();

        self::assertArrayNotHasKey('retries', $settings);
        self::assertArrayNotHasKey('http', $settings);
        self::assertArrayNotHasKey('endpoint', $settings);
    }

    /**
     * @param  array<string, mixed>  $overrides
     */
    private function settings(array $overrides = []): AwsClientSettings
    {
        $config = array_replace_recursive(self::validConfig(), $overrides);

        return new AwsClientSettings(DiskConfiguration::fromArray($config));
    }

    /**
     * @return array<string, mixed>
     */
    private static function validConfig(): array
    {
        return [
            'key' => 'disk-key',
            'secret' => 'disk-secret',
            'region' => 'disk-region',
            'bucket' => 'bucket',
            'kms' => [
                'key_id' => 'kms-key-id',
            ],
        ];
    }
}
