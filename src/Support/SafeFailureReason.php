<?php

declare(strict_types=1);

namespace J1nn0\EncryptedS3\Support;

use Aws\Exception\AwsException;
use Throwable;

/**
 * Reduces a throwable to a reason safe to put in an exception message.
 *
 * Crypto path failures carry plaintext, credentials, KMS key material, and
 * envelope values in their messages and context. Only the short class name and
 * an AWS error code ever leave this class.
 *
 * @internal
 */
final class SafeFailureReason
{
    public static function from(Throwable $exception): string
    {
        $class = $exception::class;
        $separator = strrpos($class, '\\');
        $reason = $separator === false ? $class : substr($class, $separator + 1);

        for ($current = $exception; $current !== null; $current = $current->getPrevious()) {
            if (! $current instanceof AwsException) {
                continue;
            }

            $errorCode = $current->getAwsErrorCode();

            if ($errorCode !== null && $errorCode !== '') {
                return $reason.' ('.$errorCode.')';
            }

            break;
        }

        return $reason;
    }
}
