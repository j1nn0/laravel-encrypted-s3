<?php

declare(strict_types=1);

namespace J1nn0\EncryptedS3\Filesystem;

use Illuminate\Filesystem\FilesystemAdapter;
use J1nn0\EncryptedS3\Exceptions\UnsupportedOperationException;

final class EncryptedS3Filesystem extends FilesystemAdapter
{
    public function url($path)
    {
        throw new UnsupportedOperationException(
            'Public URLs are not supported because they would serve ciphertext without client-side decryption.'
        );
    }

    /**
     * @param  array<string, mixed>  $options
     */
    public function temporaryUrl($path, $expiration, array $options = []): string
    {
        throw new UnsupportedOperationException(
            'Presigned GET URLs are not supported because they bypass client-side decryption and return ciphertext.'
        );
    }

    /**
     * @param  array<string, mixed>  $options
     * @return array<string, mixed>
     */
    public function temporaryUploadUrl($path, $expiration, array $options = []): array
    {
        throw new UnsupportedOperationException(
            'Presigned PUT URLs are not supported because they bypass client-side encryption and could store plaintext in S3.'
        );
    }

    public function providesTemporaryUrls(): bool
    {
        return false;
    }

    public function providesTemporaryUploadUrls(): bool
    {
        return false;
    }
}
