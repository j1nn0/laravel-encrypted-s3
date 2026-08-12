<?php

declare(strict_types=1);

namespace J1nn0\EncryptedS3\Tests\Integration;

use Aws\Crypto\MetadataEnvelope;
use Illuminate\Support\Facades\Storage;
use League\Flysystem\UnableToReadFile;
use Psr\Http\Message\StreamInterface;
use RuntimeException;

final class MotoIntegrationTest extends TestCase
{
    public function test_encrypted_storage_round_trips_plaintext_over_http(): void
    {
        $plain = 'moto HTTP integration plaintext';

        Storage::disk()->put('round-trip.txt', $plain);

        self::assertSame($plain, Storage::disk()->get('round-trip.txt'));
    }

    public function test_download_returns_the_plaintext_length_and_body_over_http(): void
    {
        $key = 'download-binary.dat';
        $plain = "\x00\xff\x01\xfe".str_repeat("\xa5\x5a", 2048)."\x00\x80\xff";
        $disk = Storage::disk();

        $disk->put($key, $plain);

        $size = $disk->size($key);
        self::assertNotSame(strlen($plain), $size);

        $response = $disk->download($key, 'download-binary.dat');
        $contentLength = $response->headers->get('Content-Length');
        self::assertNotNull($contentLength);
        self::assertSame((string) strlen($plain), $contentLength);
        self::assertNotSame((string) $size, $contentLength);

        ob_start();
        $response->sendContent();
        $body = ob_get_clean();

        self::assertSame($plain, $body);
    }

    public function test_ciphertext_at_rest_is_not_plaintext_over_http(): void
    {
        $plain = 'plaintext must not appear in the raw S3 object';

        Storage::disk()->put('ciphertext.txt', $plain);

        $raw = $this->s3->getObject([
            'Bucket' => $this->bucket,
            'Key' => 'ciphertext.txt',
        ]);
        $body = $raw['Body'] ?? null;

        if (! $body instanceof StreamInterface) {
            throw new RuntimeException('Moto returned a non-stream S3 response body.');
        }

        $ciphertext = (string) $body;

        self::assertNotSame($plain, $ciphertext);
        self::assertStringNotContainsString($plain, $ciphertext);
    }

    public function test_v3_envelope_is_in_header_metadata_without_an_instruction_file(): void
    {
        $key = 'header-metadata.txt';

        Storage::disk()->put($key, 'header metadata plaintext');

        $raw = $this->s3->getObject([
            'Bucket' => $this->bucket,
            'Key' => $key,
        ]);
        $metadata = $raw['Metadata'] ?? null;
        self::assertIsArray($metadata);

        foreach (MetadataEnvelope::getV3Fields() as $field) {
            self::assertArrayHasKey($field, $metadata);
        }

        $listing = $this->s3->listObjectsV2(['Bucket' => $this->bucket]);
        $contents = $listing['Contents'] ?? [];
        $objectKeys = [];

        if (is_array($contents)) {
            foreach ($contents as $object) {
                $objectKey = is_array($object) ? ($object['Key'] ?? null) : null;

                if (is_string($objectKey)) {
                    $objectKeys[] = $objectKey;
                }
            }
        }

        self::assertContains($key, $objectKeys);
        self::assertNotContains($key.'.instruction', $objectKeys);
    }

    public function test_wrong_kms_key_cannot_decrypt_an_existing_object(): void
    {
        $key = 'kms-bound.txt';
        Storage::disk()->put($key, 'KMS-bound plaintext');

        $wrongKeyId = $this->createKmsKey();
        $this->configureDisk(['kms' => ['key_id' => $wrongKeyId]]);

        try {
            // Storage::get consumes the response body, which makes Moto verify the GCM tag.
            Storage::disk()->get($key);
            self::fail('An object encrypted with another KMS key was decrypted.');
        } catch (UnableToReadFile $exception) {
            self::assertStringContainsString('AccessDeniedException', $exception->getMessage());
        }
    }

    public function test_stream_write_and_read_round_trip_over_http(): void
    {
        $plain = 'streamed plaintext over Moto HTTP';
        $writeStream = fopen('php://temp', 'w+b');
        self::assertIsResource($writeStream);
        fwrite($writeStream, $plain);
        rewind($writeStream);

        Storage::disk()->writeStream('stream.txt', $writeStream);
        fclose($writeStream);

        $readStream = Storage::disk()->readStream('stream.txt');
        self::assertIsResource($readStream);
        $contents = stream_get_contents($readStream);
        fclose($readStream);

        self::assertSame($plain, $contents);
    }
}
