# ADR 0001: Metadata strategy pins

The put-side `@MetadataStrategy` pin is redundant with the AWS SDK default, which returns `HeadersMetadataStrategy` in `vendor/aws/aws-sdk-php/src/S3/Crypto/S3EncryptionClientV3.php:154-157`, but it remains intentional so this package does not depend on that SDK default; the get-side pin is load-bearing because `vendor/aws/aws-sdk-php/src/S3/Crypto/CryptoParamsTrait.php:29-43` falls back to `InstructionFileMetadataStrategy` when an object has no envelope headers, so removing it would restore the GHSA-x8cp-jf6f-r4xh attack surface.
