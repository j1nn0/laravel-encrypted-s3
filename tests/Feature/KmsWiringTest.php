<?php

declare(strict_types=1);

namespace J1nn0\EncryptedS3\Tests\Feature;

use Aws\Crypto\MetadataEnvelope;
use Illuminate\Support\Facades\Storage;
use J1nn0\EncryptedS3\Tests\TestCase;
use League\Flysystem\UnableToReadFile;
use League\Flysystem\UnableToWriteFile;
use PHPUnit\Framework\Attributes\DataProvider;
use Throwable;

final class KmsWiringTest extends TestCase
{
    public function test_delete_directory_deletes_nested_objects(): void
    {
        $disk = Storage::disk();
        $disk->makeDirectory('folder');
        $disk->put('folder/file.txt', 'file body');
        $disk->put('folder/nested/nested-file.txt', 'nested file body');

        self::assertTrue($disk->deleteDirectory('folder'));
        self::assertArrayNotHasKey('folder/', $this->aws->objects);
        self::assertArrayNotHasKey('folder/file.txt', $this->aws->objects);
        self::assertArrayNotHasKey('folder/nested/nested-file.txt', $this->aws->objects);
    }

    public function test_kms_falls_back_to_disk_region_and_credentials_and_accepts_overrides(): void
    {
        Storage::disk()->put('fallback.txt', 'fallback plaintext');
        $this->assertKmsEndpointAndScope(
            $this->lastKmsRequest('GenerateDataKey'),
            'kms.us-east-1.amazonaws.com',
            'access-key',
            'us-east-1',
        );

        $this->configureDisk([
            'kms' => [
                'region' => 'ap-northeast-1',
                'key' => 'kms-access-key',
                'secret' => 'kms-secret-key',
            ],
        ]);
        Storage::disk()->put('explicit.txt', 'explicit plaintext');

        $this->assertKmsEndpointAndScope(
            $this->lastKmsRequest('GenerateDataKey'),
            'kms.ap-northeast-1.amazonaws.com',
            'kms-access-key',
            'ap-northeast-1',
        );
    }

    public function test_allow_decrypt_with_any_cmk_only_omits_decrypt_key_id(): void
    {
        Storage::disk()->put('default.txt', 'default plaintext');
        $defaultGenerate = $this->kmsBody($this->lastKmsRequest('GenerateDataKey'));
        self::assertSame('kms-key-id', $defaultGenerate['KeyId'] ?? null);

        self::assertSame('default plaintext', Storage::disk()->get('default.txt'));
        $defaultDecrypt = $this->kmsBody($this->lastKmsRequest('Decrypt'));
        self::assertSame('kms-key-id', $defaultDecrypt['KeyId'] ?? null);

        $this->configureDisk([
            'encryption' => [
                'allow_decrypt_with_any_cmk' => true,
            ],
        ]);
        Storage::disk()->put('any-cmk.txt', 'any cmk plaintext');
        $anyCmkGenerate = $this->kmsBody($this->lastKmsRequest('GenerateDataKey'));
        self::assertSame('kms-key-id', $anyCmkGenerate['KeyId'] ?? null);

        self::assertSame('any cmk plaintext', Storage::disk()->get('any-cmk.txt'));
        $anyCmkDecrypt = $this->kmsBody($this->lastKmsRequest('Decrypt'));
        self::assertArrayNotHasKey('KeyId', $anyCmkDecrypt);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function kmsErrorProvider(): iterable
    {
        yield 'access denied' => ['AccessDeniedException'];
        yield 'incorrect key' => ['IncorrectKeyException'];
    }

    #[DataProvider('kmsErrorProvider')]
    public function test_kms_errors_become_unable_to_read_without_leaking_sensitive_values(string $errorCode): void
    {
        $plain = 'kms-error plaintext must stay secret';
        Storage::disk()->put('kms-error.txt', $plain);
        $this->aws->failKmsWith($errorCode);

        try {
            Storage::disk()->get('kms-error.txt');
            self::fail('The KMS error was not propagated as a read failure.');
        } catch (UnableToReadFile $exception) {
            self::assertSame('KmsException ('.$errorCode.')', $exception->reason());

            foreach ([
                $plain,
                'deterministic-ciphertext-blob',
                '01234567890123456789012345678901',
                'access-key',
                'secret-key',
                'kms-key-id',
            ] as $secret) {
                self::assertStringNotContainsString($secret, $exception->getMessage());
            }
        }
    }

    public function test_encrypted_failure_messages_do_not_reemit_sensitive_values_from_the_full_exception_chain(): void
    {
        $plain = 'exception-chain plaintext must stay secret';
        $sensitiveValues = [
            $plain,
            'deterministic-ciphertext-blob',
            '01234567890123456789012345678901',
            'access-key',
            'secret-key',
            'kms-key-id',
        ];
        $failureMessage = "KMS denied key kms-key-id for plaintext {$plain}; data key "
            .'01234567890123456789012345678901 and ciphertext '
            .'deterministic-ciphertext-blob were handled with access-key/secret-key.';

        Storage::disk()->put('read-failure.txt', $plain);
        $this->aws->failKmsWith('AccessDeniedException', $failureMessage);

        try {
            Storage::disk()->get('read-failure.txt');
            self::fail('The KMS read error was not propagated.');
        } catch (UnableToReadFile $exception) {
            $this->assertExceptionChainDoesNotReemitSensitiveValues($exception, $sensitiveValues, $failureMessage);
            self::assertSame('KmsException (AccessDeniedException)', $exception->reason());
        }

        $this->aws->failKmsWith('AccessDeniedException', $failureMessage);

        try {
            Storage::disk()->put('write-failure.txt', $plain);
            self::fail('The KMS write error was not propagated.');
        } catch (UnableToWriteFile $exception) {
            $this->assertExceptionChainDoesNotReemitSensitiveValues($exception, $sensitiveValues, $failureMessage);
            self::assertSame('KmsException (AccessDeniedException)', $exception->reason());
        }
    }

    public function test_kms_wire_contains_v3_context_and_round_trips_the_envelope(): void
    {
        $this->configureDisk([
            'encryption' => [
                'encryption_context' => [
                    'tenant' => 'tenant-a',
                    'purpose' => 'wire-test',
                ],
            ],
        ]);

        Storage::disk()->put('wire.txt', 'wire plaintext');
        $generate = $this->kmsBody($this->lastKmsRequest('GenerateDataKey'));
        self::assertSame('kms-key-id', $generate['KeyId'] ?? null);
        self::assertSame('AES_256', $generate['KeySpec'] ?? null);
        self::assertSame([
            'tenant' => 'tenant-a',
            'purpose' => 'wire-test',
            'aws:x-amz-cek-alg' => '115',
        ], $generate['EncryptionContext'] ?? null);

        self::assertSame('wire plaintext', Storage::disk()->get('wire.txt'));
        $decrypt = $this->kmsBody($this->lastKmsRequest('Decrypt'));
        self::assertSame($generate['EncryptionContext'], $decrypt['EncryptionContext'] ?? null);

        $envelopeHeader = 'x-amz-meta-'.MetadataEnvelope::ENCRYPTED_DATA_KEY_V3;
        $envelope = $this->aws->objects['wire.txt']['headers'][$envelopeHeader] ?? null;
        self::assertIsString($envelope);
        self::assertSame($envelope, $decrypt['CiphertextBlob'] ?? null);
    }

    /**
     * @return array{target: string, body: string, headers: array<string, string>, uri: string}
     */
    private function lastKmsRequest(string $operation): array
    {
        foreach (array_reverse($this->aws->kmsRequests) as $request) {
            if (str_ends_with($request['target'], '.'.$operation)) {
                return $request;
            }
        }

        self::fail('No KMS '.$operation.' request was recorded.');
    }

    /**
     * @param  array{target: string, body: string, headers: array<string, string>, uri: string}  $request
     * @return array<string, mixed>
     */
    private function kmsBody(array $request): array
    {
        $body = json_decode($request['body'], true, 512, JSON_THROW_ON_ERROR);
        self::assertIsArray($body);

        return $body;
    }

    /**
     * @param  array{target: string, body: string, headers: array<string, string>, uri: string}  $request
     */
    private function assertKmsEndpointAndScope(
        array $request,
        string $host,
        string $accessKey,
        string $region,
    ): void {
        self::assertStringContainsString($host, $request['uri']);

        $authorization = $request['headers']['authorization'] ?? '';
        self::assertStringContainsString('Credential='.$accessKey.'/', $authorization);
        self::assertStringContainsString('/'.$region.'/kms/aws4_request', $authorization);
    }

    /**
     * @param  list<string>  $sensitiveValues
     */
    private function assertExceptionChainDoesNotReemitSensitiveValues(
        Throwable $exception,
        array $sensitiveValues,
        string $upstreamMessage,
    ): void {
        $messages = [];

        for ($current = $exception; $current !== null; $current = $current->getPrevious()) {
            $messages[] = $current->getMessage();
        }

        self::assertNotNull($exception->getPrevious());
        $lastMessage = $messages[count($messages) - 1];
        self::assertSame($upstreamMessage, $lastMessage);

        // Assert messages only; PHP stack-trace arguments are outside package control.
        foreach ($sensitiveValues as $sensitiveValue) {
            self::assertStringContainsString($sensitiveValue, $lastMessage);
        }

        foreach (array_slice($messages, 0, -1) as $message) {
            foreach ($sensitiveValues as $sensitiveValue) {
                self::assertStringNotContainsString($sensitiveValue, $message);
            }
        }
    }
}
