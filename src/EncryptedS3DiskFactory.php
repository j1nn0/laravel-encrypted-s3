<?php

declare(strict_types=1);

namespace J1nn0\EncryptedS3;

use Aws\Crypto\KmsMaterialsProviderV3;
use Aws\Kms\KmsClient;
use Aws\S3\Crypto\S3EncryptionClientV3;
use Aws\S3\S3Client;
use J1nn0\EncryptedS3\Filesystem\EncryptedS3Filesystem;
use J1nn0\EncryptedS3\Flysystem\EncryptedS3Adapter;
use J1nn0\EncryptedS3\Support\AwsClientSettings;
use J1nn0\EncryptedS3\Support\DiskConfiguration;
use J1nn0\EncryptedS3\Support\EncryptedS3Arguments;
use J1nn0\EncryptedS3\Support\ObjectLocation;
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
        $diskConfiguration = DiskConfiguration::fromArray($config);
        $clientSettings = new AwsClientSettings($diskConfiguration);
        $visibility = new PortableVisibilityConverter;
        $mimeTypeDetector = new FinfoMimeTypeDetector;
        $location = new ObjectLocation($diskConfiguration->bucket(), $diskConfiguration->root());
        $s3Client = new S3Client($clientSettings->forS3());
        $kmsClient = new KmsClient($clientSettings->forKms());
        $materialsProvider = new KmsMaterialsProviderV3($kmsClient, $diskConfiguration->kmsKeyId());
        $encryptionClient = new S3EncryptionClientV3($s3Client);
        $inner = new AwsS3V3Adapter(
            $s3Client,
            $location->bucket(),
            $location->root(),
            $visibility,
            $mimeTypeDetector,
        );

        $putOptions = $diskConfiguration->putOptions();

        $arguments = new EncryptedS3Arguments(
            $materialsProvider,
            $location,
            $mimeTypeDetector,
            $visibility,
            $diskConfiguration->encryptionOptions(),
            $putOptions,
        );
        $adapter = new EncryptedS3Adapter(
            $encryptionClient,
            $inner,
            $arguments,
        );
        $filesystem = new Filesystem($adapter, $diskConfiguration->raw());

        return new EncryptedS3Filesystem($filesystem, $adapter, $diskConfiguration->raw());
    }
}
