<?php

declare(strict_types=1);

namespace J1nn0\EncryptedS3\Tests\Integration;

use Aws\Kms\KmsClient;
use Aws\S3\S3Client;
use GuzzleHttp\Client;
use J1nn0\EncryptedS3\EncryptedS3ServiceProvider;
use Orchestra\Testbench\TestCase as OrchestraTestCase;
use RuntimeException;
use Throwable;

abstract class TestCase extends OrchestraTestCase
{
    protected const MOTO_ENDPOINT = 'http://127.0.0.1:5000';

    protected const REGION = 'us-east-1';

    protected S3Client $s3;

    protected KmsClient $kms;

    protected string $bucket;

    protected string $kmsKeyId;

    private bool $testbenchSetUp = false;

    protected function setUp(): void
    {
        $this->s3 = new S3Client($this->s3Config());
        $this->kms = new KmsClient($this->kmsConfig());
        $this->ensureMotoIsAvailable();
        $this->bucket = 'encrypted-s3-integration-'.bin2hex(random_bytes(12));
        $this->s3->createBucket(['Bucket' => $this->bucket]);
        $this->kmsKeyId = $this->createKmsKey();

        parent::setUp();
        $this->testbenchSetUp = true;
    }

    protected function tearDown(): void
    {
        try {
            if (isset($this->bucket)) {
                $this->removeMotoBucket();
            }
        } finally {
            if ($this->testbenchSetUp) {
                parent::tearDown();
            }
        }
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
            'key' => 'testing',
            'secret' => 'testing',
            'region' => self::REGION,
            'bucket' => $this->bucket,
            'endpoint' => self::MOTO_ENDPOINT,
            'use_path_style_endpoint' => true,
            'root' => '',
            'throw' => true,
            'options' => [],
            'kms' => [
                'key_id' => $this->kmsKeyId,
                'endpoint' => self::MOTO_ENDPOINT,
            ],
            'encryption' => [
                'commitment_policy' => 'REQUIRE_ENCRYPT_REQUIRE_DECRYPT',
                'security_profile' => 'V3',
                'encryption_context' => ['suite' => 'moto-integration'],
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

    protected function createKmsKey(): string
    {
        $result = $this->kms->createKey([
            'KeyUsage' => 'ENCRYPT_DECRYPT',
            'KeySpec' => 'SYMMETRIC_DEFAULT',
            'Description' => 'laravel-encrypted-s3 integration test',
        ]);
        $keyId = $result['KeyMetadata']['KeyId'] ?? null;

        if (! is_string($keyId) || $keyId === '') {
            throw new RuntimeException('Moto returned no KMS key ID from CreateKey.');
        }

        return $keyId;
    }

    /**
     * @return array<string, mixed>
     */
    private function s3Config(): array
    {
        return [
            'version' => 'latest',
            'region' => self::REGION,
            'endpoint' => self::MOTO_ENDPOINT,
            'use_path_style_endpoint' => true,
            'credentials' => ['key' => 'testing', 'secret' => 'testing'],
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private function kmsConfig(): array
    {
        return [
            'version' => 'latest',
            'region' => self::REGION,
            'endpoint' => self::MOTO_ENDPOINT,
            'credentials' => ['key' => 'testing', 'secret' => 'testing'],
        ];
    }

    private function ensureMotoIsAvailable(): void
    {
        try {
            $response = (new Client([
                'connect_timeout' => 0.5,
                'timeout' => 1.0,
                'http_errors' => false,
            ]))->get(self::MOTO_ENDPOINT.'/moto-api/');
        } catch (Throwable $exception) {
            throw new RuntimeException($this->motoUnavailableMessage(), 0, $exception);
        }

        if ($response->getStatusCode() !== 200) {
            throw new RuntimeException($this->motoUnavailableMessage());
        }
    }

    private function motoUnavailableMessage(): string
    {
        return 'Moto Server is unavailable at '.self::MOTO_ENDPOINT
            .'. Run `docker compose up -d --wait` before running integration tests.';
    }

    private function removeMotoBucket(): void
    {
        $result = $this->s3->listObjectsV2(['Bucket' => $this->bucket]);
        $contents = $result['Contents'] ?? [];
        $objects = [];

        if (is_array($contents)) {
            foreach ($contents as $object) {
                $key = is_array($object) ? ($object['Key'] ?? null) : null;

                if (is_string($key)) {
                    $objects[] = ['Key' => $key];
                }
            }
        }

        if ($objects !== []) {
            $this->s3->deleteObjects([
                'Bucket' => $this->bucket,
                'Delete' => ['Objects' => $objects, 'Quiet' => true],
            ]);
        }

        $this->s3->deleteBucket(['Bucket' => $this->bucket]);
    }
}
