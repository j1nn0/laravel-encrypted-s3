<?php

declare(strict_types=1);

namespace J1nn0\EncryptedS3\Tests\Unit;

use Aws\Command;
use Aws\Kms\Exception\KmsException;
use Aws\S3\Exception\S3Exception;
use J1nn0\EncryptedS3\Support\SafeFailureReason;
use PHPUnit\Framework\TestCase;
use RuntimeException;

final class SafeFailureReasonTest extends TestCase
{
    private const PLAINTEXT = 'attack at dawn';

    private const SECRET = 'AKIAIOSFODNN7EXAMPLE';

    public function test_a_plain_throwable_is_reduced_to_its_short_class_name(): void
    {
        self::assertSame('RuntimeException', SafeFailureReason::from(new RuntimeException('boom')));
    }

    public function test_a_namespaced_throwable_keeps_only_the_short_class_name(): void
    {
        $exception = new S3Exception('Not found.', new Command('GetObject'));

        self::assertSame('S3Exception', SafeFailureReason::from($exception));
    }

    public function test_an_aws_error_code_is_appended(): void
    {
        $exception = new KmsException('KMS request failed.', new Command('Decrypt'), [
            'code' => 'AccessDeniedException',
        ]);

        self::assertSame('KmsException (AccessDeniedException)', SafeFailureReason::from($exception));
    }

    public function test_an_aws_error_code_is_found_through_the_previous_chain(): void
    {
        $exception = new RuntimeException('wrapper', 0, new KmsException(
            'KMS request failed.',
            new Command('Decrypt'),
            ['code' => 'KMSInvalidStateException'],
        ));

        self::assertSame('RuntimeException (KMSInvalidStateException)', SafeFailureReason::from($exception));
    }

    public function test_a_missing_aws_error_code_leaves_the_short_class_name_alone(): void
    {
        $exception = new KmsException('KMS request failed.', new Command('Decrypt'));

        self::assertSame('KmsException', SafeFailureReason::from($exception));
    }

    public function test_the_reason_never_carries_plaintext_credentials_or_key_material(): void
    {
        $exception = new RuntimeException(
            'Decryption failed for '.self::PLAINTEXT.' using '.self::SECRET,
            0,
            new KmsException(
                'Invalid key arn:aws:kms:us-east-1:111122223333:key/'.self::SECRET,
                new Command('Decrypt', ['CiphertextBlob' => self::PLAINTEXT]),
                ['code' => 'AccessDeniedException'],
            ),
        );

        $reason = SafeFailureReason::from($exception);

        self::assertSame('RuntimeException (AccessDeniedException)', $reason);
        self::assertStringNotContainsString(self::PLAINTEXT, $reason);
        self::assertStringNotContainsString(self::SECRET, $reason);
        self::assertStringNotContainsString('arn:aws:kms', $reason);
    }
}
