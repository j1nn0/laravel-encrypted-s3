<?php

declare(strict_types=1);

namespace J1nn0\EncryptedS3\Support;

use Aws\Crypto\MaterialsProviderV3;
use Aws\S3\Crypto\HeadersMetadataStrategy;
use J1nn0\EncryptedS3\Exceptions\InvalidConfigurationException;
use League\Flysystem\AwsS3V3\VisibilityConverter;
use League\Flysystem\Config;
use League\MimeTypeDetection\MimeTypeDetector;

/**
 * @internal
 */
final class EncryptedS3Arguments
{
    private const OPTION_MIMETYPE = 'mimetype';

    /**
     * @param  array<string, mixed>  $defaultPutOptions
     */
    public function __construct(
        private readonly MaterialsProviderV3 $materialsProvider,
        private readonly ObjectLocation $location,
        private readonly MimeTypeDetector $mimeTypeDetector,
        private readonly VisibilityConverter $visibility,
        private readonly EncryptionOptions $encryptionOptions,
        private readonly array $defaultPutOptions = [],
    ) {}

    /**
     * @param  string|resource  $contents
     * @return array<string, mixed>
     */
    public function forPut(string $path, $contents, Config $config): array
    {
        $options = $this->optionsForConfig($config);
        $configuredMimeType = $config->get(self::OPTION_MIMETYPE);

        if (is_string($configuredMimeType) && $configuredMimeType !== '') {
            $options['ContentType'] = $configuredMimeType;
        } elseif (! array_key_exists('ContentType', $options)) {
            $detectedMimeType = $this->mimeTypeDetector->detectMimeType($path, $contents);

            if ($detectedMimeType !== null) {
                $options['ContentType'] = $detectedMimeType;
            }
        }

        $arguments = array_merge(
            $options,
            $this->commonArguments($path),
            [
                'Body' => $contents,
                '@CipherOptions' => ['Cipher' => 'gcm'],
            ],
        );

        PutOptions::assertAclAndGrantsAreNotCombined($arguments);

        return $arguments;
    }

    /**
     * @return array{
     *     sourceBucket: string,
     *     sourceKey: string,
     *     destinationBucket: string,
     *     destinationKey: string,
     *     acl: mixed,
     *     options: array{
     *         MetadataDirective: string,
     *         params: array<string, mixed>,
     *     },
     * }
     */
    public function forCopy(string $source, string $destination, Config $config): array
    {
        $this->assertCopyMetadataDirective($config);

        $options = $this->optionsForConfig($config);
        PutOptions::assertAclAndGrantsAreNotCombined($options);
        $acl = $options['ACL'] ?? null;
        unset($options['ACL']);

        return [
            'sourceBucket' => $this->location->bucket(),
            'sourceKey' => $this->location->key($source),
            'destinationBucket' => $this->location->bucket(),
            'destinationKey' => $this->location->key($destination),
            'acl' => $acl,
            'options' => [
                // CSE V3 envelope headers must be copied with the object.
                'MetadataDirective' => 'COPY',
                'params' => $options,
            ],
        ];
    }

    /**
     * @return array<string, mixed>
     */
    public function forGet(string $path): array
    {
        return array_merge(
            $this->commonArguments($path),
            [
                '@SecurityProfile' => $this->encryptionOptions->securityProfile,
                '@KmsAllowDecryptWithAnyCmk' => $this->encryptionOptions->allowDecryptWithAnyCmk,
            ],
        );
    }

    /**
     * @return array<string, mixed>
     */
    private function commonArguments(string $path): array
    {
        return [
            'Bucket' => $this->location->bucket(),
            'Key' => $this->location->key($path),
            '@MaterialsProvider' => $this->materialsProvider,
            '@CommitmentPolicy' => $this->encryptionOptions->commitmentPolicy,
            '@KmsEncryptionContext' => $this->encryptionOptions->encryptionContext,
            '@MetadataStrategy' => HeadersMetadataStrategy::class,
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private function optionsForConfig(Config $config): array
    {
        $options = array_merge(
            PutOptions::filtered($this->defaultPutOptions),
            PutOptions::filtered($config->toArray()),
        );
        $configuredVisibility = $config->get(Config::OPTION_VISIBILITY);

        if (is_string($configuredVisibility) && $configuredVisibility !== '') {
            $options['ACL'] = $this->visibility->visibilityToAcl($configuredVisibility);
        }

        return $options;
    }

    private function assertCopyMetadataDirective(Config $config): void
    {
        $metadataDirective = $config->get('MetadataDirective');

        if (
            $metadataDirective === null
            || (is_string($metadataDirective) && strtoupper($metadataDirective) === 'COPY')
        ) {
            return;
        }

        // Reject REPLACE instead of silently overriding it so the envelope pin is visible to callers.
        throw new InvalidConfigurationException(
            'The S3 copy option MetadataDirective must be COPY to preserve client-side encryption metadata.',
        );
    }
}
