<?php

declare(strict_types=1);

namespace J1nn0\EncryptedS3\Tests;

use J1nn0\EncryptedS3\EncryptedS3ServiceProvider;
use J1nn0\EncryptedS3\Tests\Support\InMemoryAws;
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
        $config = array_replace_recursive($this->diskConfig(), $overrides);
        $this->app['config']->set('filesystems.disks.encrypted-s3', $config);
        $this->app['filesystem']->forgetDisk('encrypted-s3');
    }
}
