<?php

declare(strict_types=1);

namespace J1nn0\EncryptedS3\Exceptions;

use RuntimeException;

/**
 * Carries a redacted copy failure reason safe to surface to callers.
 *
 * @internal
 */
final class CopyFailedException extends RuntimeException {}
