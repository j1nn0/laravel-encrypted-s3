<?php

declare(strict_types=1);

namespace J1nn0\EncryptedS3\Tests\Unit;

use Aws\Crypto\MaterialsProviderV3;
use Aws\Result;
use Aws\S3\Crypto\S3EncryptionClientV3;
use Aws\S3\S3ClientInterface;
use J1nn0\EncryptedS3\Flysystem\EncryptedS3Adapter;
use J1nn0\EncryptedS3\Support\EncryptedS3Arguments;
use J1nn0\EncryptedS3\Support\EncryptionOptions;
use J1nn0\EncryptedS3\Support\ObjectLocation;
use League\Flysystem\AwsS3V3\AwsS3V3Adapter;
use League\Flysystem\AwsS3V3\VisibilityConverter;
use League\Flysystem\UnableToReadFile;
use League\MimeTypeDetection\MimeTypeDetector;
use PHPUnit\Framework\TestCase;

final class EncryptedS3AdapterTest extends TestCase
{
    public function test_read_rejects_a_non_stream_response_body(): void
    {
        $arguments = new EncryptedS3Arguments(
            $this->createMock(MaterialsProviderV3::class),
            new ObjectLocation('bucket', ''),
            $this->createMock(MimeTypeDetector::class),
            $this->createMock(VisibilityConverter::class),
            new EncryptionOptions(
                EncryptionOptions::COMMITMENT_POLICY_REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
                EncryptionOptions::SECURITY_PROFILE_V3,
                [],
                false,
            ),
        );
        $encryptionClient = $this->createMock(S3EncryptionClientV3::class);
        $encryptionClient->method('getObject')->willReturn(new Result(['Body' => null]));
        $adapter = new EncryptedS3Adapter(
            $encryptionClient,
            $this->createStub(S3ClientInterface::class),
            $this->createStub(AwsS3V3Adapter::class),
            $arguments,
        );

        $this->expectException(UnableToReadFile::class);

        $adapter->read('file.txt');
    }
}
