<?php

declare(strict_types=1);

namespace J1nn0\EncryptedS3\Flysystem;

use Aws\Crypto\MaterialsProviderV3;
use Aws\Exception\AwsException;
use Aws\S3\Crypto\HeadersMetadataStrategy;
use Aws\S3\Crypto\S3EncryptionClientV3;
use J1nn0\EncryptedS3\Support\EncryptionOptions;
use League\Flysystem\AwsS3V3\AwsS3V3Adapter;
use League\Flysystem\AwsS3V3\VisibilityConverter;
use League\Flysystem\Config;
use League\Flysystem\FileAttributes;
use League\Flysystem\FilesystemAdapter;
use League\Flysystem\PathPrefixer;
use League\Flysystem\UnableToReadFile;
use League\Flysystem\UnableToWriteFile;
use League\MimeTypeDetection\MimeTypeDetector;
use Psr\Http\Message\StreamInterface;
use RuntimeException;
use Throwable;

final class EncryptedS3Adapter implements FilesystemAdapter
{
    private const OPTION_MIMETYPE = 'mimetype';

    /**
     * @param  array<string, mixed>  $defaultPutOptions
     */
    public function __construct(
        private readonly S3EncryptionClientV3 $encryptionClient,
        private readonly MaterialsProviderV3 $materialsProvider,
        private readonly AwsS3V3Adapter $inner,
        private readonly string $bucket,
        private readonly PathPrefixer $prefixer,
        private readonly MimeTypeDetector $mimeTypeDetector,
        private readonly VisibilityConverter $visibility,
        private readonly EncryptionOptions $encryptionOptions,
        private readonly array $defaultPutOptions = [],
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
            $result = $this->encryptionClient->getObject($this->getArguments($path));

            return (string) $result['Body'];
        } catch (Throwable $exception) {
            throw UnableToReadFile::fromLocation($path, $this->exceptionReason($exception), $exception);
        }
    }

    public function readStream(string $path)
    {
        try {
            $result = $this->encryptionClient->getObject($this->getArguments($path));
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
            throw UnableToReadFile::fromLocation($path, $this->exceptionReason($exception), $exception);
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
        $this->inner->createDirectory($path, $config);
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
        $this->inner->move($source, $destination, $config);
    }

    public function copy(string $source, string $destination, Config $config): void
    {
        $this->inner->copy($source, $destination, $config);
    }

    /**
     * @param  string|resource  $contents
     */
    private function put(string $path, $contents, Config $config): void
    {
        try {
            $this->encryptionClient->putObject($this->putArguments($path, $contents, $config));
        } catch (Throwable $exception) {
            throw UnableToWriteFile::atLocation($path, $this->exceptionReason($exception), $exception);
        }
    }

    /**
     * @param  string|resource  $contents
     * @return array<string, mixed>
     */
    private function putArguments(string $path, $contents, Config $config): array
    {
        $options = array_merge(
            $this->filterPutOptions($this->defaultPutOptions),
            $this->filterPutOptions($config->toArray()),
        );
        $configuredMimeType = $config->get(self::OPTION_MIMETYPE);
        $configuredVisibility = $config->get(Config::OPTION_VISIBILITY);

        if (is_string($configuredVisibility) && $configuredVisibility !== '') {
            $options['ACL'] = $this->visibility->visibilityToAcl($configuredVisibility);
        }

        if (is_string($configuredMimeType) && $configuredMimeType !== '') {
            $options['ContentType'] = $configuredMimeType;
        } elseif (! array_key_exists('ContentType', $options)) {
            $detectedMimeType = $this->mimeTypeDetector->detectMimeType($path, $contents);

            if ($detectedMimeType !== null) {
                $options['ContentType'] = $detectedMimeType;
            }
        }

        $options['Bucket'] = $this->bucket;
        $options['Key'] = $this->prefixer->prefixPath($path);
        $options['Body'] = $contents;
        $options['@MaterialsProvider'] = $this->materialsProvider;
        $options['@CommitmentPolicy'] = $this->encryptionOptions->commitmentPolicy;
        $options['@CipherOptions'] = ['Cipher' => 'gcm'];
        $options['@KmsEncryptionContext'] = $this->encryptionOptions->encryptionContext;
        $options['@MetadataStrategy'] = HeadersMetadataStrategy::class;

        return $options;
    }

    /**
     * @param  array<mixed, mixed>  $options
     * @return array<string, mixed>
     */
    private function filterPutOptions(array $options): array
    {
        $filtered = [];

        foreach ($options as $key => $value) {
            if (! is_string($key) || $key === 'Metadata') {
                continue;
            }

            if (in_array($key, ['Body', 'Bucket', 'Key'], true) || str_starts_with($key, '@')) {
                continue;
            }

            if (in_array($key, AwsS3V3Adapter::AVAILABLE_OPTIONS, true)) {
                $filtered[$key] = $value;
            }
        }

        return $filtered;
    }

    private function exceptionReason(Throwable $exception): string
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

    /**
     * @return array<string, mixed>
     */
    private function getArguments(string $path): array
    {
        return [
            'Bucket' => $this->bucket,
            'Key' => $this->prefixer->prefixPath($path),
            '@MaterialsProvider' => $this->materialsProvider,
            '@CommitmentPolicy' => $this->encryptionOptions->commitmentPolicy,
            '@SecurityProfile' => $this->encryptionOptions->securityProfile,
            '@KmsEncryptionContext' => $this->encryptionOptions->encryptionContext,
            '@KmsAllowDecryptWithAnyCmk' => $this->encryptionOptions->allowDecryptWithAnyCmk,
            '@MetadataStrategy' => HeadersMetadataStrategy::class,
        ];
    }
}
