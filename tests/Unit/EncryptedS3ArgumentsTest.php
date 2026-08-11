<?php

declare(strict_types=1);

namespace J1nn0\EncryptedS3\Tests\Unit;

use Aws\Crypto\MaterialsProviderV3;
use Aws\S3\Crypto\HeadersMetadataStrategy;
use Aws\S3\Crypto\InstructionFileMetadataStrategy;
use J1nn0\EncryptedS3\Support\EncryptedS3Arguments;
use J1nn0\EncryptedS3\Support\EncryptionOptions;
use League\Flysystem\AwsS3V3\VisibilityConverter;
use League\Flysystem\Config;
use League\Flysystem\PathPrefixer;
use League\MimeTypeDetection\MimeTypeDetector;
use PHPUnit\Framework\TestCase;

final class EncryptedS3ArgumentsTest extends TestCase
{
    private EncryptedS3Arguments $arguments;

    protected function setUp(): void
    {
        parent::setUp();

        $mimeTypeDetector = $this->createMock(MimeTypeDetector::class);
        $mimeTypeDetector->method('detectMimeType')->willReturn(null);

        $this->arguments = new EncryptedS3Arguments(
            $this->createMock(MaterialsProviderV3::class),
            'bucket',
            new PathPrefixer('root'),
            $mimeTypeDetector,
            $this->createMock(VisibilityConverter::class),
            new EncryptionOptions(
                EncryptionOptions::COMMITMENT_POLICY_REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
                EncryptionOptions::SECURITY_PROFILE_V3,
                [],
                false,
            ),
        );
    }

    public function test_put_and_get_pin_headers_metadata_strategy(): void
    {
        $put = $this->arguments->forPut('file.txt', 'contents', new Config);
        $get = $this->arguments->forGet('file.txt');

        self::assertSame(HeadersMetadataStrategy::class, $put['@MetadataStrategy']);
        self::assertSame(HeadersMetadataStrategy::class, $get['@MetadataStrategy']);
    }

    public function test_get_contains_decryption_security_options(): void
    {
        $get = $this->arguments->forGet('file.txt');

        self::assertSame(EncryptionOptions::SECURITY_PROFILE_V3, $get['@SecurityProfile']);
        self::assertFalse($get['@KmsAllowDecryptWithAnyCmk']);
    }

    public function test_for_put_replaces_or_removes_reserved_options(): void
    {
        $put = $this->arguments->forPut('file.txt', 'contents', new Config([
            'Metadata' => ['unsafe' => 'value'],
            'Body' => 'unsafe',
            'Bucket' => 'unsafe',
            'Key' => 'unsafe',
            '@MetadataStrategy' => InstructionFileMetadataStrategy::class,
            '@Injected' => 'unsafe',
        ]));

        self::assertArrayNotHasKey('Metadata', $put);
        self::assertSame('contents', $put['Body']);
        self::assertSame('bucket', $put['Bucket']);
        self::assertSame('root/file.txt', $put['Key']);
        self::assertSame(HeadersMetadataStrategy::class, $put['@MetadataStrategy']);
        self::assertArrayNotHasKey('@Injected', $put);
    }
}
