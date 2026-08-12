<?php

declare(strict_types=1);

namespace J1nn0\EncryptedS3\Tests;

use Illuminate\Config\Repository;
use Illuminate\Filesystem\FilesystemManager;
use Illuminate\Foundation\Application;
use J1nn0\EncryptedS3\EncryptedS3ServiceProvider;
use J1nn0\EncryptedS3\Tests\Support\InMemoryAws;
use LogicException;
use Orchestra\Testbench\TestCase as OrchestraTestCase;

abstract class TestCase extends OrchestraTestCase
{
    protected InMemoryAws $aws;

    protected function setUp(): void
    {
        $this->aws = new InMemoryAws;

        parent::setUp();
    }

    protected function getPackageProviders($app): array
    {
        return [EncryptedS3ServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('filesystems.default', 'encrypted-s3');
        $app['config']->set('filesystems.disks.encrypted-s3', $this->diskConfig());
    }

    /**
     * @return array<string, mixed>
     */
    protected function diskConfig(): array
    {
        return [
            'driver' => 'encrypted-s3',
            'key' => 'access-key',
            'secret' => 'secret-key',
            'region' => 'us-east-1',
            'bucket' => 'test-bucket',
            'endpoint' => 'http://s3.test',
            'use_path_style_endpoint' => true,
            'root' => '',
            'throw' => true,
            'options' => [],
            'handler' => $this->aws->s3Handler(),
            'kms' => [
                'key_id' => 'kms-key-id',
                'region' => null,
                'handler' => $this->aws->kmsHandler(),
            ],
            'encryption' => [
                'commitment_policy' => 'REQUIRE_ENCRYPT_REQUIRE_DECRYPT',
                'security_profile' => 'V3',
                'encryption_context' => [],
                'allow_decrypt_with_any_cmk' => false,
            ],
        ];
    }

    /**
     * @param  array<string, mixed>  $overrides
     */
    protected function configureDisk(array $overrides): void
    {
        $config = $this->stringKeyedConfig(array_replace_recursive($this->diskConfig(), $overrides));
        $this->setDiskConfig($config);
    }

    /**
     * @param  array<string, mixed>  $config
     */
    protected function setDiskConfig(array $config): void
    {
        $app = $this->app;

        if (! $app instanceof Application) {
            throw new LogicException('The test application is not available.');
        }

        $app->make(Repository::class)->set('filesystems.disks.encrypted-s3', $config);
        $app->make(FilesystemManager::class)->forgetDisk('encrypted-s3');
    }

    /**
     * @param  array<mixed, mixed>  $config
     * @return array<string, mixed>
     */
    private function stringKeyedConfig(array $config): array
    {
        $validated = [];

        foreach ($config as $key => $value) {
            if (! is_string($key)) {
                throw new LogicException('The test configuration must have string keys.');
            }

            $validated[$key] = $value;
        }

        return $validated;
    }
}
