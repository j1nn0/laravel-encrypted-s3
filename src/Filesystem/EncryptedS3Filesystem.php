<?php

declare(strict_types=1);

namespace J1nn0\EncryptedS3\Filesystem;

use Illuminate\Filesystem\FilesystemAdapter;
use J1nn0\EncryptedS3\Exceptions\UnsupportedOperationException;
use League\Flysystem\UnableToRetrieveMetadata;
use Symfony\Component\HttpFoundation\StreamedResponse;

final class EncryptedS3Filesystem extends FilesystemAdapter
{
    /**
     * Create a streamed response for a given file.
     *
     * @param  string  $path
     * @param  string|null  $name
     * @param  array<string, mixed>  $headers
     * @param  string|null  $disposition
     * @return StreamedResponse
     *
     * @throws UnableToRetrieveMetadata
     */
    public function response($path, $name = null, array $headers = [], $disposition = 'inline')
    {
        $response = new StreamedResponse;
        $stream = $this->readStream($path);
        $stat = is_resource($stream) ? fstat($stream) : false;

        $headers['Content-Type'] ??= $this->mimeType($path);

        if ($stat !== false) {
            $headers['Content-Length'] ??= $stat['size'];
        }

        if (! array_key_exists('Content-Disposition', $headers)) {
            $filename = $name ?? basename($path);

            $disposition = $response->headers->makeDisposition(
                $disposition, $filename, $this->fallbackName($filename)
            );

            $headers['Content-Disposition'] = $disposition;
        }

        $response->headers->replace($headers);

        $response->setCallback(function () use ($stream) {
            if (! is_resource($stream)) {
                return;
            }

            fpassthru($stream);
            fclose($stream);
        });

        return $response;
    }

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
