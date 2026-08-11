<?php

declare(strict_types=1);

namespace J1nn0\EncryptedS3\Tests\Feature;

use Aws\Crypto\MetadataEnvelope;
use Closure;
use DateTimeImmutable;
use Illuminate\Support\Facades\Storage;
use J1nn0\EncryptedS3\Exceptions\InvalidConfigurationException;
use J1nn0\EncryptedS3\Exceptions\UnsupportedOperationException;
use J1nn0\EncryptedS3\Filesystem\EncryptedS3Filesystem;
use J1nn0\EncryptedS3\Support\EncryptionOptions;
use J1nn0\EncryptedS3\Tests\TestCase;
use League\Flysystem\UnableToReadFile;
use PHPUnit\Framework\Attributes\DataProvider;

final class EncryptedS3FilesystemTest extends TestCase
{
    public function test_put_encrypts_the_body_and_does_not_send_plaintext(): void
    {
        $plain = 'highly-sensitive-plaintext';

        Storage::disk()->put('secret.txt', $plain);

        $ciphertext = $this->aws->objects['secret.txt']['body'];

        self::assertStringNotContainsString($plain, $ciphertext);
        self::assertNotSame($plain, $ciphertext);
        self::assertSame(strlen($plain) + 16, strlen($ciphertext));
    }

    public function test_put_sends_cse_envelope_metadata(): void
    {
        Storage::disk()->put('secret.txt', 'secret');

        $metadata = array_filter(
            array_keys($this->aws->objects['secret.txt']['headers']),
            static fn (string $key): bool => str_starts_with($key, 'x-amz-meta-x-amz-')
        );

        self::assertNotEmpty($metadata);
    }

    public function test_tampered_ciphertext_fails_closed_without_leaking_plaintext(): void
    {
        $plain = 'do-not-return-this-plaintext';
        Storage::disk()->put('tampered.txt', $plain);
        $ciphertext = $this->aws->objects['tampered.txt']['body'];
        $ciphertext[0] = chr(ord($ciphertext[0]) ^ 1);
        $this->aws->objects['tampered.txt']['body'] = $ciphertext;

        try {
            Storage::disk()->get('tampered.txt');
            self::fail('Tampered ciphertext was accepted.');
        } catch (UnableToReadFile $exception) {
            self::assertStringNotContainsString($plain, $exception->getMessage());
            self::assertStringNotContainsString('kms-key-id', $exception->getMessage());
            self::assertStringContainsString('CryptoException', $exception->getMessage());
        }
    }

    public function test_encryption_context_mismatch_fails(): void
    {
        $this->configureDisk([
            'encryption' => [
                'encryption_context' => ['tenant' => 'one'],
            ],
        ]);
        Storage::disk()->put('context.txt', 'context-bound');

        $this->configureDisk([
            'encryption' => [
                'encryption_context' => ['tenant' => 'two'],
            ],
        ]);

        $this->expectException(UnableToReadFile::class);
        Storage::disk()->get('context.txt');
    }

    public function test_object_without_encryption_envelope_is_not_returned_as_plaintext(): void
    {
        $this->aws->putRaw('legacy.txt', 'legacy-body', [
            'content-type' => 'text/plain',
        ]);

        try {
            Storage::disk()->get('legacy.txt');
            self::fail('An object without an encryption envelope was returned as plaintext.');
        } catch (UnableToReadFile $exception) {
            self::assertStringNotContainsString('legacy-body', $exception->getMessage());
        }

        $this->assertNoInstructionFileRequests();
    }

    public function test_existing_instruction_file_is_not_read(): void
    {
        $this->aws->putRaw('legacy-with-instruction.txt', 'legacy-body');
        $this->aws->putRaw('legacy-with-instruction.txt.instruction', 'instruction-body');

        try {
            Storage::disk()->get('legacy-with-instruction.txt');
            self::fail('An object without an encryption envelope was returned as plaintext.');
        } catch (UnableToReadFile $exception) {
            self::assertStringNotContainsString('legacy-body', $exception->getMessage());
        }

        $this->assertNoInstructionFileRequests();
    }

    public function test_allow_decrypt_commitment_policy_does_not_read_instruction_files(): void
    {
        $this->configureDisk([
            'encryption' => [
                'commitment_policy' => EncryptionOptions::COMMITMENT_POLICY_REQUIRE_ENCRYPT_ALLOW_DECRYPT,
                'security_profile' => EncryptionOptions::SECURITY_PROFILE_V3,
            ],
        ]);
        $this->aws->putRaw('legacy-opt-in.txt', 'legacy-body');

        try {
            Storage::disk()->get('legacy-opt-in.txt');
            self::fail('An object without an encryption envelope was returned as plaintext.');
        } catch (UnableToReadFile $exception) {
            self::assertStringNotContainsString('legacy-body', $exception->getMessage());
        }

        $this->assertS3GetRequestWasIssued();
        $this->assertNoInstructionFileRequests();
    }

    public function test_require_decrypt_commitment_policy_rejects_a_v2_envelope(): void
    {
        $this->configureDisk([
            'encryption' => [
                'security_profile' => 'V3',
            ],
        ]);

        $this->aws->putRaw('v2.txt', 'legacy ciphertext', [
            'x-amz-meta-'.MetadataEnvelope::CONTENT_KEY_V2_HEADER => 'legacy-key',
            'x-amz-meta-'.MetadataEnvelope::IV_HEADER => 'legacy-iv',
            'x-amz-meta-'.MetadataEnvelope::MATERIALS_DESCRIPTION_HEADER => '{}',
            'x-amz-meta-'.MetadataEnvelope::KEY_WRAP_ALGORITHM_HEADER => 'kms',
            'x-amz-meta-'.MetadataEnvelope::CONTENT_CRYPTO_SCHEME_HEADER => 'AES/GCM/NoPadding',
            'x-amz-meta-'.MetadataEnvelope::CRYPTO_TAG_LENGTH_HEADER => '128',
        ]);

        try {
            Storage::disk()->get('v2.txt');
            self::fail('A V2 envelope was accepted with the V3 security profile.');
        } catch (UnableToReadFile $exception) {
            self::assertStringContainsString('CryptoException', $exception->getMessage());
            self::assertStringContainsString('commitment policy', strtolower($exception->getPrevious()?->getMessage() ?? ''));
        }
    }

    public function test_v3_security_profile_rejects_a_v2_envelope(): void
    {
        $this->configureDisk([
            'encryption' => [
                'commitment_policy' => EncryptionOptions::COMMITMENT_POLICY_REQUIRE_ENCRYPT_ALLOW_DECRYPT,
                'security_profile' => EncryptionOptions::SECURITY_PROFILE_V3,
            ],
        ]);

        $this->aws->putRaw('v2-security-profile.txt', 'legacy ciphertext', [
            'x-amz-meta-'.MetadataEnvelope::CONTENT_KEY_V2_HEADER => 'legacy-key',
            'x-amz-meta-'.MetadataEnvelope::IV_HEADER => 'legacy-iv',
            'x-amz-meta-'.MetadataEnvelope::MATERIALS_DESCRIPTION_HEADER => '{}',
            'x-amz-meta-'.MetadataEnvelope::KEY_WRAP_ALGORITHM_HEADER => 'kms',
            'x-amz-meta-'.MetadataEnvelope::CONTENT_CRYPTO_SCHEME_HEADER => 'AES/GCM/NoPadding',
            'x-amz-meta-'.MetadataEnvelope::CRYPTO_TAG_LENGTH_HEADER => '128',
        ]);

        try {
            Storage::disk()->get('v2-security-profile.txt');
            self::fail('A V2 envelope was accepted with the V3 security profile.');
        } catch (UnableToReadFile $exception) {
            self::assertStringContainsString('CryptoException', $exception->getMessage());
            self::assertStringContainsString('securityprofile=v3', strtolower($exception->getPrevious()?->getMessage() ?? ''));
        }
    }

    public function test_url_operations_are_always_unsupported(): void
    {
        /** @var EncryptedS3Filesystem $disk */
        $disk = Storage::disk();
        $disk->buildTemporaryUrlsUsing(static fn (): string => 'https://example.test');

        foreach (['url', 'temporaryUrl', 'temporaryUploadUrl'] as $operation) {
            try {
                if ($operation === 'url') {
                    $disk->url('file.txt');
                } elseif ($operation === 'temporaryUrl') {
                    $disk->temporaryUrl('file.txt', new DateTimeImmutable('+1 hour'));
                } else {
                    $disk->temporaryUploadUrl('file.txt', new DateTimeImmutable('+1 hour'));
                }

                self::fail($operation.' unexpectedly returned a URL.');
            } catch (UnsupportedOperationException) {
            }
        }

        self::assertFalse($disk->providesTemporaryUrls());
        self::assertFalse($disk->providesTemporaryUploadUrls());
    }

    /**
     * @return iterable<string, array{array<string, mixed>}>
     */
    public static function invalidConfigurationProvider(): iterable
    {
        yield 'missing kms key' => [['kms' => ['key_id' => null]]];
        yield 'invalid commitment policy' => [['encryption' => ['commitment_policy' => 'INVALID']]];
        yield 'invalid security profile' => [['encryption' => ['security_profile' => 'LEGACY']]];
        yield 'forbidden commitment policy' => [['encryption' => ['commitment_policy' => EncryptionOptions::COMMITMENT_POLICY_FORBID_ENCRYPT_ALLOW_DECRYPT]]];
        yield 'legacy security profile' => [['encryption' => ['security_profile' => EncryptionOptions::SECURITY_PROFILE_V3_AND_LEGACY]]];
        yield 'reserved encryption context key' => [['encryption' => ['encryption_context' => ['kms_cmk_id' => 'x']]]];
        yield 'metadata option' => [['options' => ['Metadata' => ['unsafe' => 'value']]]];
    }

    /**
     * @param  array<string, mixed>  $overrides
     */
    #[DataProvider('invalidConfigurationProvider')]
    public function test_invalid_configuration_is_rejected_immediately(array $overrides): void
    {
        $this->configureDisk($overrides);

        $this->expectException(InvalidConfigurationException::class);
        Storage::disk();
    }

    public function test_incompatible_put_option_is_rejected_at_disk_construction_time(): void
    {
        $this->configureDisk(['options' => ['ContentLength' => 123]]);

        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('The S3 put option ContentLength is incompatible with client-side encryption.');

        Storage::disk();
    }

    public function test_legacy_security_profile_is_rejected_with_a_security_reason(): void
    {
        $this->configureDisk([
            'encryption' => [
                'security_profile' => EncryptionOptions::SECURITY_PROFILE_V3_AND_LEGACY,
            ],
        ]);

        $this->assertConfigurationRejected(
            static fn (): mixed => Storage::disk(),
            ['V3_AND_LEGACY', 'GHSA-x8cp-jf6f-r4xh', 'CVE-2025-14761', 'ErrorException'],
        );
    }

    public function test_uncommitted_writes_policy_is_rejected_with_a_security_reason(): void
    {
        $this->configureDisk([
            'encryption' => [
                'commitment_policy' => EncryptionOptions::COMMITMENT_POLICY_FORBID_ENCRYPT_ALLOW_DECRYPT,
            ],
        ]);

        $this->assertConfigurationRejected(
            static fn (): mixed => Storage::disk(),
            ['FORBID_ENCRYPT_ALLOW_DECRYPT', 'GHSA-x8cp-jf6f-r4xh', 'CVE-2025-14761', 'REQUIRE_ENCRYPT_ALLOW_DECRYPT'],
        );
    }

    public function test_put_and_get_round_trip_plaintext(): void
    {
        $plain = "hello\x00encrypted\xff";

        self::assertTrue(Storage::disk()->put('round-trip.bin', $plain));
        self::assertSame($plain, Storage::disk()->get('round-trip.bin'));
    }

    public function test_write_stream_and_read_stream_round_trip_binary_content(): void
    {
        $plain = "\x00\x01\x02binary\xff\xfe";
        $writeStream = fopen('php://memory', 'w+b');
        self::assertIsResource($writeStream);
        fwrite($writeStream, $plain);
        rewind($writeStream);

        Storage::disk()->writeStream('stream.bin', $writeStream);
        $readStream = Storage::disk()->readStream('stream.bin');

        self::assertIsResource($readStream);
        self::assertSame($plain, stream_get_contents($readStream));
    }

    public function test_write_stream_encrypts_the_body_before_sending(): void
    {
        $plain = 'stream plaintext must not reach S3';
        $writeStream = fopen('php://memory', 'w+b');
        self::assertIsResource($writeStream);
        fwrite($writeStream, $plain);
        rewind($writeStream);

        Storage::disk()->writeStream('encrypted-stream.txt', $writeStream);

        $ciphertext = $this->aws->objects['encrypted-stream.txt']['body'];
        self::assertStringNotContainsString($plain, $ciphertext);
        self::assertNotSame($plain, $ciphertext);
        self::assertSame(strlen($plain) + 16, strlen($ciphertext));
    }

    public function test_size_is_the_ciphertext_size(): void
    {
        $plain = 'sized plaintext';
        Storage::disk()->put('sized.txt', $plain);

        self::assertSame(strlen($plain) + 16, Storage::disk()->size('sized.txt'));
    }

    public function test_checksum_is_calculated_from_plaintext(): void
    {
        $plain = 'checksum plaintext';
        /** @var EncryptedS3Filesystem $disk */
        $disk = Storage::disk();
        $disk->put('checksum.txt', $plain);

        self::assertSame(md5($plain), $disk->checksum('checksum.txt'));
    }

    public function test_mime_type_can_be_set_at_write_time(): void
    {
        /** @var EncryptedS3Filesystem $disk */
        $disk = Storage::disk();
        $disk->put('mime.bin', 'mime body', ['mimetype' => 'application/x-encrypted-test']);

        self::assertSame('application/x-encrypted-test', $disk->mimeType('mime.bin'));
    }

    public function test_only_allowlisted_s3_put_options_are_forwarded(): void
    {
        Storage::disk()->put('options.txt', 'option body', [
            'CacheControl' => 'max-age=60',
            'Metadata' => ['unsafe' => 'value'],
            'Bucket' => 'attacker-bucket',
            'Key' => 'attacker-key',
            '@CommitmentPolicy' => 'unsafe-policy',
            'custom_option' => 'must-not-be-forwarded',
        ]);

        $request = $this->aws->lastS3Request('PUT');
        self::assertIsArray($request);
        self::assertSame('max-age=60', $request['headers']['cache-control'] ?? null);
        self::assertStringNotContainsString('attacker-key', $request['path']);
        self::assertArrayNotHasKey('x-amz-meta-unsafe', $request['headers']);
        self::assertArrayNotHasKey('custom-option', $request['headers']);
    }

    public function test_a_disk_with_an_unsupported_put_option_is_rejected_at_construction(): void
    {
        $this->configureDisk([
            'options' => ['CacheContol' => 'max-age=60'],
        ]);

        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage(
            'The S3 put option CacheContol is not supported by client-side encryption.',
        );

        Storage::disk();
    }

    public function test_a_disk_without_a_visibility_key_sends_no_acl(): void
    {
        $config = $this->diskConfig();
        unset($config['visibility']);
        $this->app['config']->set('filesystems.disks.encrypted-s3', $config);
        $this->app['filesystem']->forgetDisk('encrypted-s3');

        Storage::disk()->put('no-visibility.txt', 'body');

        $request = $this->aws->lastS3Request('PUT');
        self::assertIsArray($request);
        self::assertArrayNotHasKey('x-amz-acl', $request['headers']);
    }

    public function test_a_disk_with_an_explicit_acl_option_sends_that_acl(): void
    {
        $this->configureDisk([
            'options' => ['ACL' => 'bucket-owner-full-control'],
        ]);

        Storage::disk()->put('explicit-acl.txt', 'body');

        $request = $this->aws->lastS3Request('PUT');
        self::assertIsArray($request);
        self::assertSame('bucket-owner-full-control', $request['headers']['x-amz-acl'] ?? null);
    }

    public function test_disk_visibility_overrides_an_explicit_acl_option(): void
    {
        $this->configureDisk([
            'options' => ['ACL' => 'bucket-owner-full-control'],
            'visibility' => 'private',
        ]);

        Storage::disk()->put('visibility-overrides-acl.txt', 'body');

        $request = $this->aws->lastS3Request('PUT');
        self::assertIsArray($request);
        self::assertSame('private', $request['headers']['x-amz-acl'] ?? null);
    }

    public function test_a_disk_with_private_visibility_sends_a_private_acl(): void
    {
        $this->configureDisk(['visibility' => 'private']);

        Storage::disk()->put('private-visibility.txt', 'body');

        $request = $this->aws->lastS3Request('PUT');
        self::assertIsArray($request);
        self::assertSame('private', $request['headers']['x-amz-acl'] ?? null);
    }

    public function test_a_disk_with_public_visibility_sends_a_public_acl(): void
    {
        $this->configureDisk(['visibility' => 'public']);

        Storage::disk()->put('public-visibility.txt', 'body');

        $request = $this->aws->lastS3Request('PUT');
        self::assertIsArray($request);
        self::assertSame('public-read', $request['headers']['x-amz-acl'] ?? null);
    }

    public function test_a_per_call_visibility_option_sends_the_matching_acl(): void
    {
        Storage::disk()->put('per-call-visibility.txt', 'body', ['visibility' => 'public']);

        $request = $this->aws->lastS3Request('PUT');
        self::assertIsArray($request);
        self::assertSame('public-read', $request['headers']['x-amz-acl'] ?? null);
    }

    public function test_copy_and_move_preserve_the_envelope_and_remain_readable(): void
    {
        Storage::disk()->put('source.txt', 'copyable plaintext');
        $sourceEnvelope = $this->envelopeHeaders('source.txt');
        Storage::disk()->copy('source.txt', 'copy.txt');

        self::assertSame('copyable plaintext', Storage::disk()->get('copy.txt'));
        $copyRequest = $this->aws->lastS3Request('PUT');
        self::assertIsArray($copyRequest);
        self::assertArrayHasKey('x-amz-metadata-directive', $copyRequest['headers']);
        self::assertSame('COPY', strtoupper($copyRequest['headers']['x-amz-metadata-directive']));
        self::assertSame($sourceEnvelope, $this->envelopeHeaders('copy.txt'));

        Storage::disk()->move('copy.txt', 'moved.txt');

        self::assertFalse(Storage::disk()->exists('copy.txt'));
        self::assertSame('copyable plaintext', Storage::disk()->get('moved.txt'));
    }

    /**
     * @return array<string, string>
     */
    private function envelopeHeaders(string $key): array
    {
        return array_filter(
            $this->aws->objects[$key]['headers'],
            static fn (string $header): bool => str_starts_with($header, 'x-amz-meta-x-amz-'),
            ARRAY_FILTER_USE_KEY,
        );
    }

    /**
     * @param  Closure(): mixed  $operation
     * @param  list<string>  $expectedFragments
     */
    private function assertConfigurationRejected(Closure $operation, array $expectedFragments): void
    {
        try {
            $operation();
            self::fail('The invalid configuration was accepted.');
        } catch (InvalidConfigurationException $exception) {
            foreach ($expectedFragments as $expectedFragment) {
                self::assertStringContainsString($expectedFragment, $exception->getMessage());
            }
        }
    }

    private function assertNoInstructionFileRequests(): void
    {
        $instructionRequests = array_filter(
            $this->aws->s3Requests,
            static fn (array $request): bool => str_contains($request['path'], '.instruction'),
        );

        self::assertCount(0, $instructionRequests);
    }

    private function assertS3GetRequestWasIssued(): void
    {
        $getRequests = array_filter(
            $this->aws->s3Requests,
            static fn (array $request): bool => $request['method'] === 'GET',
        );

        self::assertNotEmpty($getRequests);
    }

    public function test_basic_metadata_listing_and_delete_operations(): void
    {
        /** @var EncryptedS3Filesystem $disk */
        $disk = Storage::disk();
        $disk->makeDirectory('folder');
        $disk->put('folder/file.txt', 'file body');

        self::assertTrue($disk->exists('folder/file.txt'));
        self::assertTrue($disk->directoryExists('folder'));
        self::assertContains('folder/file.txt', $disk->files('folder'));
        self::assertContains('folder', $disk->directories());
        self::assertGreaterThan(0, $disk->lastModified('folder/file.txt'));
        self::assertTrue($disk->delete('folder/file.txt'));
        self::assertFalse($disk->exists('folder/file.txt'));
        self::assertTrue($disk->deleteDirectory('folder'));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function rootProvider(): iterable
    {
        yield 'empty root' => [''];
        yield 'root prefix' => ['root-prefix'];
        yield 'root prefix with trailing slash' => ['root-prefix/'];
        yield 'nested root prefix' => ['a/b'];
    }

    #[DataProvider('rootProvider')]
    public function test_root_prefix_is_used_consistently_for_encrypted_and_delegated_operations(string $root): void
    {
        $this->configureDisk(['root' => $root]);
        $disk = Storage::disk();
        $prefix = rtrim($root, '\\/');
        $expectedKey = $prefix === '' ? 'rooted.txt' : $prefix.'/rooted.txt';
        $expectedCopyKey = $prefix === '' ? 'rooted-copy.txt' : $prefix.'/rooted-copy.txt';

        $disk->put('rooted.txt', 'rooted plaintext');

        self::assertArrayHasKey($expectedKey, $this->aws->objects);
        self::assertTrue($disk->exists('rooted.txt'));
        self::assertSame('rooted plaintext', $disk->get('rooted.txt'));

        $listedPaths = [];
        foreach ($disk->listContents('', true) as $attribute) {
            $listedPaths[] = $attribute->path();
        }
        self::assertContains('rooted.txt', $listedPaths);

        $disk->copy('rooted.txt', 'rooted-copy.txt');
        self::assertSame('rooted plaintext', $disk->get('rooted-copy.txt'));
        self::assertArrayHasKey($expectedCopyKey, $this->aws->objects);

        $listedPaths = [];
        foreach ($disk->listContents('', true) as $attribute) {
            $listedPaths[] = $attribute->path();
        }
        self::assertContains('rooted-copy.txt', $listedPaths);
    }

    public function test_storage_disk_integration_uses_the_discovered_provider(): void
    {
        $disk = Storage::disk('encrypted-s3');

        self::assertInstanceOf(EncryptedS3Filesystem::class, $disk);
        self::assertTrue($disk->put('integrated.txt', 'integrated plaintext'));
        self::assertSame('integrated plaintext', $disk->get('integrated.txt'));
    }
}
