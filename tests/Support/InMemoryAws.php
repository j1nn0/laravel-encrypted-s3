<?php

declare(strict_types=1);

namespace J1nn0\EncryptedS3\Tests\Support;

use Aws\Api\DateTimeResult;
use Aws\CommandInterface;
use Aws\Kms\Exception\KmsException;
use Aws\Result;
use Aws\S3\Exception\S3Exception;
use GuzzleHttp\Promise\Create;
use GuzzleHttp\Psr7\Response;
use GuzzleHttp\Psr7\Utils;
use LogicException;
use Psr\Http\Message\RequestInterface;

final class InMemoryAws
{
    /**
     * @var array<string, array{body: string, headers: array<string, string>, last_modified: string}>
     */
    public array $objects = [];

    /**
     * @var list<array{method: string, path: string, headers: array<string, string>, body: string}>
     */
    public array $s3Requests = [];

    /**
     * @var list<array{target: string, body: string, headers: array<string, string>, uri: string}>
     */
    public array $kmsRequests = [];

    private string $dataKey = '01234567890123456789012345678901';

    private string $ciphertextBlob = 'deterministic-ciphertext-blob';

    private ?string $kmsErrorCode = null;

    private ?string $kmsErrorMessage = null;

    public function s3Handler(): callable
    {
        return function (CommandInterface $command, RequestInterface $request) {
            return Create::promiseFor($this->handleS3($command, $request));
        };
    }

    public function kmsHandler(): callable
    {
        return function (CommandInterface $command, RequestInterface $request) {
            return Create::promiseFor($this->handleKms($command, $request));
        };
    }

    public function failKmsWith(string $errorCode, string $message = 'KMS request failed.'): void
    {
        $this->kmsErrorCode = $errorCode;
        $this->kmsErrorMessage = $message;
    }

    /**
     * @param  array<string, string>  $headers
     */
    public function putRaw(string $key, string $body, array $headers = []): void
    {
        $this->objects[$key] = [
            'body' => $body,
            'headers' => $headers + [
                'content-type' => 'application/octet-stream',
            ],
            'last_modified' => gmdate('D, d M Y H:i:s \G\M\T'),
        ];
    }

    /**
     * @return array{method: string, path: string, headers: array<string, string>, body: string}|null
     */
    public function lastS3Request(string $method): ?array
    {
        for ($index = count($this->s3Requests) - 1; $index >= 0; $index--) {
            if ($this->s3Requests[$index]['method'] === $method) {
                return $this->s3Requests[$index];
            }
        }

        return null;
    }

    // @phpstan-ignore-next-line missingType.iterableValue
    private function handleS3(CommandInterface $command, RequestInterface $request): Result
    {
        $requestBody = (string) $request->getBody();
        $requestHeaders = $this->headers($request);
        $path = rawurldecode(ltrim($request->getUri()->getPath(), '/'));
        $bucketSeparator = strpos($path, '/');
        $key = $bucketSeparator === false ? '' : substr($path, $bucketSeparator + 1);
        $method = strtoupper($request->getMethod());

        $this->s3Requests[] = [
            'method' => $method,
            'path' => $path,
            'headers' => $requestHeaders,
            'body' => $requestBody,
        ];

        return match ($command->getName()) {
            'PutObject' => $this->putObject($key, $requestBody, $requestHeaders),
            'GetObject' => $this->getObject($command, $key),
            'HeadObject' => $this->headObject($command, $key),
            'DeleteObject' => $this->deleteObject($key),
            'DeleteObjects' => $this->deleteObjects($command),
            'CopyObject' => $this->copyObject($command, $request, $key, $requestHeaders),
            'ListObjects' => $this->listObjects($command),
            'ListObjectsV2' => $this->listObjects($command),
            'PutObjectAcl' => new Result,
            'GetObjectAcl' => new Result(['Grants' => $this->grants()]),
            default => throw new LogicException(
                'InMemoryAws received an unhandled S3 command: '.$command->getName()
            ),
        };
    }

    // @phpstan-ignore-next-line missingType.iterableValue
    private function handleKms(CommandInterface $command, RequestInterface $request): Result
    {
        $target = $request->getHeaderLine('X-Amz-Target');
        $body = (string) $request->getBody();
        $this->kmsRequests[] = [
            'target' => $target,
            'body' => $body,
            'headers' => $this->headers($request),
            'uri' => (string) $request->getUri(),
        ];

        $errorCode = $this->kmsErrorCode;
        $errorMessage = $this->kmsErrorMessage ?? 'KMS request failed.';
        $this->kmsErrorCode = null;
        $this->kmsErrorMessage = null;

        if ($errorCode !== null) {
            throw new KmsException($errorMessage, $command, [
                'code' => $errorCode,
                'response' => new Response(400),
            ]);
        }

        return match ($command->getName()) {
            'GenerateDataKey' => new Result([
                'CiphertextBlob' => $this->ciphertextBlob,
                'Plaintext' => $this->dataKey,
            ]),
            'Decrypt' => new Result(['Plaintext' => $this->dataKey]),
            default => throw new LogicException(
                'InMemoryAws received an unhandled KMS command: '.$command->getName()
            ),
        };
    }

    /**
     * @param  array<string, string>  $headers
     */
    // @phpstan-ignore-next-line missingType.iterableValue
    private function putObject(string $key, string $body, array $headers): Result
    {
        $this->objects[$key] = [
            'body' => $body,
            'headers' => $headers,
            'last_modified' => gmdate('D, d M Y H:i:s \G\M\T'),
        ];

        return new Result(['ETag' => '"'.md5($body).'"']);
    }

    // @phpstan-ignore-next-line missingType.iterableValue
    private function getObject(CommandInterface $command, string $key): Result
    {
        if (! isset($this->objects[$key])) {
            throw $this->notFound($command);
        }

        $object = $this->objects[$key];
        $metadata = $this->metadata($object['headers']);

        return new Result([
            'Body' => Utils::streamFor($object['body']),
            'ContentLength' => strlen($object['body']),
            'ContentType' => $this->contentType($object['headers']),
            'ETag' => '"'.md5($object['body']).'"',
            'LastModified' => DateTimeResult::fromISO8601($object['last_modified']),
            'Metadata' => $metadata,
        ]);
    }

    // @phpstan-ignore-next-line missingType.iterableValue
    private function headObject(CommandInterface $command, string $key): Result
    {
        if (! isset($this->objects[$key])) {
            throw $this->notFound($command);
        }

        $object = $this->objects[$key];

        return new Result([
            'ContentLength' => strlen($object['body']),
            'ContentType' => $this->contentType($object['headers']),
            'ETag' => '"'.md5($object['body']).'"',
            'LastModified' => DateTimeResult::fromISO8601($object['last_modified']),
            'Metadata' => $this->metadata($object['headers']),
        ]);
    }

    // @phpstan-ignore-next-line missingType.iterableValue
    private function deleteObject(string $key): Result
    {
        unset($this->objects[$key]);

        return new Result;
    }

    // @phpstan-ignore-next-line missingType.iterableValue
    private function deleteObjects(CommandInterface $command): Result
    {
        $delete = $command['Delete'] ?? [];
        $objects = is_array($delete) && is_array($delete['Objects'] ?? null)
            ? $delete['Objects']
            : [];

        foreach ($objects as $object) {
            if (is_array($object) && is_string($object['Key'] ?? null)) {
                unset($this->objects[$object['Key']]);
            }
        }

        return new Result(['Deleted' => $objects]);
    }

    /**
     * @param  array<string, string>  $requestHeaders
     */
    // @phpstan-ignore-next-line missingType.iterableValue
    private function copyObject(
        CommandInterface $command,
        RequestInterface $request,
        string $destination,
        array $requestHeaders
    ): Result {
        $source = ltrim(rawurldecode($request->getHeaderLine('x-amz-copy-source')), '/');
        $separator = strpos($source, '/');
        $sourceKey = $separator === false ? '' : substr($source, $separator + 1);

        if (! isset($this->objects[$sourceKey])) {
            throw $this->notFound($command);
        }

        $sourceObject = $this->objects[$sourceKey];
        $metadata = $sourceObject['headers'];

        if (strtoupper($request->getHeaderLine('x-amz-metadata-directive')) === 'REPLACE') {
            $metadata = $requestHeaders;
        }

        $this->objects[$destination] = [
            'body' => $sourceObject['body'],
            'headers' => $metadata,
            'last_modified' => gmdate('D, d M Y H:i:s \G\M\T'),
        ];

        return new Result(['CopyObjectResult' => ['ETag' => '"'.md5($sourceObject['body']).'"']]);
    }

    // @phpstan-ignore-next-line missingType.iterableValue
    private function listObjects(CommandInterface $command): Result
    {
        $prefix = (string) ($command['Prefix'] ?? '');
        $delimiter = (string) ($command['Delimiter'] ?? '');
        $contents = [];
        $commonPrefixes = [];

        foreach (array_keys($this->objects) as $key) {
            if (! str_starts_with($key, $prefix)) {
                continue;
            }

            $remaining = substr($key, strlen($prefix));

            if ($delimiter !== '' && str_contains($remaining, $delimiter)) {
                $commonPrefix = $prefix.substr($remaining, 0, strpos($remaining, $delimiter) + 1);
                $commonPrefixes[$commonPrefix] = true;

                continue;
            }

            $object = $this->objects[$key];
            $contents[] = [
                'Key' => $key,
                'LastModified' => DateTimeResult::fromISO8601($object['last_modified']),
                'ETag' => '"'.md5($object['body']).'"',
                'Size' => strlen($object['body']),
                'StorageClass' => 'STANDARD',
            ];
        }

        $result = [
            'IsTruncated' => false,
            'KeyCount' => count($contents) + count($commonPrefixes),
        ];

        if ($contents !== []) {
            $result['Contents'] = $contents;
        }

        if ($commonPrefixes !== []) {
            $result['CommonPrefixes'] = array_map(
                static fn (string $commonPrefix): array => ['Prefix' => $commonPrefix],
                array_keys($commonPrefixes)
            );
        }

        return new Result($result);
    }

    /**
     * @param  array<string, string>  $headers
     * @return array<string, string>
     */
    private function metadata(array $headers): array
    {
        $metadata = [];

        foreach ($headers as $name => $value) {
            if (str_starts_with(strtolower($name), 'x-amz-meta-')) {
                $metadata[substr($name, strlen('x-amz-meta-'))] = $value;
            }
        }

        return $metadata;
    }

    /**
     * @param  array<string, string>  $headers
     */
    private function contentType(array $headers): string
    {
        return $headers['content-type'] ?? $headers['Content-Type'] ?? 'application/octet-stream';
    }

    /**
     * @return list<array<string, mixed>>
     */
    private function grants(): array
    {
        return [[
            'Grantee' => ['ID' => 'owner'],
            'Permission' => 'FULL_CONTROL',
        ]];
    }

    private function notFound(CommandInterface $command): S3Exception
    {
        return new S3Exception('Not found.', $command, [
            'code' => 'NoSuchKey',
            'response' => new Response(404),
        ]);
    }

    /**
     * @return array<string, string>
     */
    private function headers(RequestInterface $request): array
    {
        $headers = [];

        foreach ($request->getHeaders() as $name => $values) {
            $headers[strtolower($name)] = implode(',', $values);
        }

        return $headers;
    }
}
