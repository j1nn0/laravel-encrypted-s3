<?php

declare(strict_types=1);

namespace J1nn0\EncryptedS3\Flysystem;

use Aws\S3\Crypto\S3EncryptionClientV3;
use Aws\S3\S3ClientInterface;
use J1nn0\EncryptedS3\Exceptions\InvalidConfigurationException;
use J1nn0\EncryptedS3\Support\EncryptedS3Arguments;
use J1nn0\EncryptedS3\Support\SafeFailureReason;
use League\Flysystem\AwsS3V3\AwsS3V3Adapter;
use League\Flysystem\Config;
use League\Flysystem\FileAttributes;
use League\Flysystem\FilesystemAdapter;
use League\Flysystem\UnableToCopyFile;
use League\Flysystem\UnableToMoveFile;
use League\Flysystem\UnableToReadFile;
use League\Flysystem\UnableToWriteFile;
use Psr\Http\Message\StreamInterface;
use RuntimeException;
use Throwable;

/**
 * @internal
 */
final class EncryptedS3Adapter implements FilesystemAdapter
{
    public function __construct(
        private readonly S3EncryptionClientV3 $encryptionClient,
        private readonly S3ClientInterface $s3Client,
        private readonly AwsS3V3Adapter $inner,
        private readonly EncryptedS3Arguments $arguments,
    ) {}

    public function fileExists(string $path): bool
    {
        return $this->inner->fileExists($path);
    }

    public function directoryExists(string $path): bool
    {
        return $this->inner->directoryExists($path);
    }

    public function write(string $path, string $contents, Config $config): void
    {
        $this->put($path, $contents, $config);
    }

    /**
     * @param  resource  $contents
     */
    public function writeStream(string $path, $contents, Config $config): void
    {
        $this->put($path, $contents, $config);
    }

    public function read(string $path): string
    {
        try {
            $result = $this->encryptionClient->getObject($this->arguments->forGet($path));
            $body = $result['Body'];

            if (! $body instanceof StreamInterface) {
                // A malformed response must fail closed instead of becoming an empty string.
                throw new RuntimeException('The encrypted response body is not a stream.');
            }

            return (string) $body;
        } catch (Throwable $exception) {
            throw UnableToReadFile::fromLocation($path, SafeFailureReason::from($exception), $exception);
        }
    }

    public function readStream(string $path)
    {
        try {
            $result = $this->encryptionClient->getObject($this->arguments->forGet($path));
            $body = $result['Body'];

            if (! $body instanceof StreamInterface) {
                throw new RuntimeException('The encrypted response body is not a stream.');
            }

            $stream = $body->detach();

            if (! is_resource($stream)) {
                throw new RuntimeException('The encrypted response stream could not be detached.');
            }

            return $stream;
        } catch (Throwable $exception) {
            throw UnableToReadFile::fromLocation($path, SafeFailureReason::from($exception), $exception);
        }
    }

    public function delete(string $path): void
    {
        $this->inner->delete($path);
    }

    public function deleteDirectory(string $path): void
    {
        $this->inner->deleteDirectory($path);
    }

    public function createDirectory(string $path, Config $config): void
    {
        $configuredVisibility = $config->get(Config::OPTION_VISIBILITY);

        if (! is_string($configuredVisibility) || $configuredVisibility === '') {
            $directoryVisibility = $config->get(Config::OPTION_DIRECTORY_VISIBILITY);

            if (is_string($directoryVisibility) && $directoryVisibility !== '') {
                // Explicit visibility wins when both are set, matching forPut()'s existing precedence.
                $config = $config->withSetting(Config::OPTION_VISIBILITY, $directoryVisibility);
            }
        }

        $this->put(rtrim($path, '/').'/', '', $config);
    }

    public function setVisibility(string $path, string $visibility): void
    {
        $this->inner->setVisibility($path, $visibility);
    }

    public function visibility(string $path): FileAttributes
    {
        return $this->inner->visibility($path);
    }

    public function mimeType(string $path): FileAttributes
    {
        return $this->inner->mimeType($path);
    }

    public function lastModified(string $path): FileAttributes
    {
        return $this->inner->lastModified($path);
    }

    public function fileSize(string $path): FileAttributes
    {
        return $this->inner->fileSize($path);
    }

    public function listContents(string $path, bool $deep): iterable
    {
        return $this->inner->listContents($path, $deep);
    }

    public function move(string $source, string $destination, Config $config): void
    {
        if ($source === $destination) {
            return;
        }

        try {
            $this->copy($source, $destination, $config);
            $this->delete($source);
        } catch (InvalidConfigurationException $exception) {
            throw $exception;
        } catch (Throwable $exception) {
            throw UnableToMoveFile::because(
                SafeFailureReason::from($exception),
                $source,
                $destination,
            );
        }
    }

    /**
     * @throws InvalidConfigurationException
     */
    public function copy(string $source, string $destination, Config $config): void
    {
        if ($source === $destination) {
            return;
        }

        try {
            $arguments = $this->arguments->forCopy($source, $destination, $config);
        } catch (InvalidConfigurationException $exception) {
            throw $exception;
        } catch (Throwable $exception) {
            throw UnableToCopyFile::because(
                SafeFailureReason::from($exception),
                $source,
                $destination,
            );
        }

        try {
            $this->s3Client->copy(
                $arguments['sourceBucket'],
                $arguments['sourceKey'],
                $arguments['destinationBucket'],
                $arguments['destinationKey'],
                // S3 skips a null ACL; its interface omits this valid case from the type.
                // @phpstan-ignore argument.type
                $arguments['acl'],
                $arguments['options'],
            );
        } catch (Throwable $exception) {
            throw UnableToCopyFile::because(
                SafeFailureReason::from($exception),
                $source,
                $destination,
            );
        }
    }

    /**
     * @param  string|resource  $contents
     */
    private function put(string $path, $contents, Config $config): void
    {
        // Argument assembly is the only phase allowed to surface an unredacted
        // message, and only for this package's own configuration exception.
        try {
            $arguments = $this->arguments->forPut($path, $contents, $config);
        } catch (InvalidConfigurationException $exception) {
            throw $exception;
        } catch (Throwable $exception) {
            throw UnableToWriteFile::atLocation($path, SafeFailureReason::from($exception), $exception);
        }

        try {
            $this->encryptionClient->putObject($arguments);
        } catch (Throwable $exception) {
            throw UnableToWriteFile::atLocation($path, SafeFailureReason::from($exception), $exception);
        }
    }
}
