# Laravel Encrypted S3

Laravel filesystem support for AWS S3 Client-Side Encryption (CSE) V3.
Encryption and decryption are delegated to the AWS SDK for PHP
`S3EncryptionClientV3` and `KmsMaterialsProviderV3`.

Client-side encryption happens in the application before data reaches S3 and
after encrypted data is downloaded. This is different from S3 server-side
encryption such as SSE-S3 and SSE-KMS: those services encrypt data inside S3,
whereas this package keeps the plaintext outside S3.

## Requirements

- PHP 8.2 or newer for Laravel 12; PHP 8.3 or newer for Laravel 13
- Laravel 12 or 13
- `ext-openssl`
- An AWS KMS key and permissions to use it
- AWS S3

The CSE V3 implementation is provided by AWS SDK for PHP 3.368 or newer.

## Installation

```sh
composer require j1nn0/laravel-encrypted-s3
```

The service provider is registered through Laravel package discovery. Add the
disk below to `config/filesystems.php`.

## Configuration

This is a complete disk configuration example:

```php
'encrypted-s3' => [
    'driver' => 'encrypted-s3',

    // The same connection keys as the standard s3 driver.
    'key'    => env('AWS_ACCESS_KEY_ID'),
    'secret' => env('AWS_SECRET_ACCESS_KEY'),
    'token'  => env('AWS_SESSION_TOKEN'),
    'region' => env('AWS_DEFAULT_REGION'),
    'bucket' => env('AWS_BUCKET'),
    'endpoint' => env('AWS_ENDPOINT'),
    'use_path_style_endpoint' => (bool) env('AWS_USE_PATH_STYLE_ENDPOINT', false),
    'retries' => ['mode' => 'standard', 'max_attempts' => 3], // Optional.
    'http' => ['timeout' => 10],                              // Optional Guzzle settings.
    'root' => '',
    // Optional: sends a canned S3 ACL. Omit this for ACL-disabled buckets.
    // 'visibility' => 'private',
    'throw' => false,
    'options' => [],          // Additional PutObject parameters.

    // Client-side encryption settings.
    'kms' => [
        'key_id' => env('AWS_ENCRYPTED_S3_KMS_KEY_ID'), // Required.
        'region' => null,        // Defaults to the disk region.
        // key, secret, and token may be supplied here; otherwise the disk
        // credentials are reused.
    ],
    'encryption' => [
        'commitment_policy'          => 'REQUIRE_ENCRYPT_REQUIRE_DECRYPT', // Allowed: REQUIRE_ENCRYPT_REQUIRE_DECRYPT, REQUIRE_ENCRYPT_ALLOW_DECRYPT.
        'security_profile'           => 'V3', // Only V3 is allowed; V3_AND_LEGACY is rejected.
        'encryption_context'         => [],
        'allow_decrypt_with_any_cmk' => false,
    ],
],
```

Only the AWS SDK client settings shown above are forwarded — `endpoint`,
`use_path_style_endpoint`, `retries`, `http`, `http_handler`, `handler`, and
`debug`. Anything else in the disk configuration is ignored rather than passed
to the SDK. The common settings may be set under `kms` for the KMS client;
`use_path_style_endpoint` is S3-only. Unlike the region and credentials, common
settings are not inherited from the disk.

`root` is an S3 key prefix. `visibility` is optional and controls the S3 ACL
for encrypted writes; when it is omitted, encrypted writes send no ACL. This
works with buckets using S3 Object Ownership = `Bucket owner enforced`. Set
`visibility` on the disk or on an individual write to send the matching canned
ACL. `throw` retains Laravel's normal filesystem exception behavior.
`options` is filtered to Flysystem's supported S3 `PutObject` parameters before
being merged into encrypted requests. `Metadata`, `Body`, `Bucket`, `Key`, and
keys beginning with `@` are reserved and rejected or omitted.

The encrypted read and write paths omit a default ACL, but delegated operations
keep the upstream Flysystem S3 behavior. `visibility()` reads the object ACL
and works on ACL-disabled buckets because AWS returns the owner's full-control
grant. `createDirectory()`, `copy()`, `move()` (which copies), and
`setVisibility()` send ACL requests and fail with
`AccessControlListNotSupported` when ACLs are disabled on the bucket.

`kms.key_id` is required; there is no unencrypted fallback. The KMS region
defaults to the disk region, and KMS credentials default to the disk
credentials. The default commitment policy and security profile are the safe
V3 settings shown above. `encryption_context` must be an associative map of
string keys and values. The reserved keys `aws:x-amz-cek-alg` and `kms_cmk_id`
cannot be configured.

`allow_decrypt_with_any_cmk` is false by default. Setting it to true permits
the SDK to try decryption without fixing the KMS key ID to the configured key.
This can make key ownership and object provenance less strict, so enable it
only for a deliberate migration or compatibility case.

## Required IAM permissions

The application credentials need, at minimum:

- `kms:GenerateDataKey` for the configured KMS key
- `kms:Decrypt` for the configured KMS key
- `s3:PutObject`
- `s3:GetObject`
- `s3:DeleteObject`
- `s3:ListBucket`
- `s3:GetObjectAcl` and `s3:PutObjectAcl` (for visibility operations)

`HeadObject` uses the `s3:GetObject` permission. S3 server-side `copy` and
`move` use `s3:GetObject` on the source and `s3:PutObject` on the destination;
there is no separate `s3:CopyObject` IAM action.

Restrict the S3 resource to the configured bucket and prefix, and restrict the
KMS resource to the intended key whenever possible.

## Usage

```php
use Illuminate\Support\Facades\Storage;

Storage::disk('encrypted-s3')->put('documents/report.txt', $contents);

$plain = Storage::disk('encrypted-s3')->get('documents/report.txt');
```

`writeStream` and `readStream` are also available, but the AWS SDK CSE V3
implementation is not streaming internally.

## Supported filesystem operations

| Operation | Support | Meaning and constraints |
| --- | --- | --- |
| `put` / `write` | Supported with constraints | Stored encrypted with CSE. No ACL is sent unless `visibility` is explicitly configured. The SDK holds the complete plaintext in memory; watch `memory_limit` for large objects. |
| `get` / `read` | Supported with constraints | Returns decrypted plaintext. The complete ciphertext is held in memory. |
| `writeStream` | Supported with constraints | Works, but is not memory-efficient because the SDK CSE implementation is non-streaming. |
| `readStream` | Supported with constraints | The returned resource is backed by decrypted plaintext held in memory. |
| `exists` / `fileExists` / `directoryExists` | Fully supported | Unrelated to encryption. |
| `delete` / `deleteDirectory` | Fully supported | Unrelated to encryption. |
| `makeDirectory` / `createDirectory` | Supported with constraints | Delegated to Flysystem's S3 adapter, which sends an ACL and fails with `AccessControlListNotSupported` when bucket ACLs are disabled. |
| `copy` | Supported with constraints | S3 server-side copy preserves the encryption envelope, so the copy remains readable. It is not re-encrypted; the original KMS encryption context is retained. The delegated adapter sends an ACL and fails when bucket ACLs are disabled. |
| `move` | Supported with constraints | Copy followed by delete, with the same ACL constraint as `copy`. |
| `size` | Supported with constraints | Returns ciphertext size, including the 16-byte GCM tag, not plaintext size. |
| `mimeType` | Supported with constraints | Returns the plaintext MIME type detected or supplied at write time. The MIME type is exposed as unencrypted S3 metadata. |
| `lastModified` | Fully supported | Unrelated to encryption. |
| `checksum` | Supported with constraints | Hashes plaintext. It downloads and decrypts the object and therefore incurs KMS and memory costs. |
| `files` / `directories` / `allFiles` / `listContents` | Fully supported | Object key names are not encrypted. |
| `visibility` | Fully supported | Reads the S3 ACL with `GetObjectAcl`; AWS returns the owner's full-control grant even when bucket ACLs are disabled. |
| `setVisibility` | Supported with constraints | Delegated to Flysystem's S3 adapter, which sends an ACL and fails with `AccessControlListNotSupported` when bucket ACLs are disabled. |
| `url` | Not supported | Throws `UnsupportedOperationException`. |
| `temporaryUrl` | Not supported | Throws `UnsupportedOperationException`. |
| `temporaryUploadUrl` | Not supported | Throws `UnsupportedOperationException`. |

## Not supported in the MVP

- Large uploads through `S3EncryptionMultipartUploaderV3`
- Instruction-file metadata strategy (intentionally disabled; only S3 object metadata is used)
- `@CipherOptions['Aad']`
- V1 or V2 format writes and legacy-format reads
- Re-encryption or key-rotation utilities
- Custom plaintext-size metadata
- Combined SSE server-side encryption support

## Constraints and security notes

- CSE V3 is non-streaming. Encryption and decryption can require several
  times the plaintext size in memory.
- `size()` is ciphertext size.
- `checksum()` is a plaintext hash and requires download, KMS decryption, and
  the associated memory and network cost.
- MIME type, object key names, and object size are not encrypted.
- `copy` and `move` preserve the existing envelope and do not re-encrypt.
- This package stores encryption envelopes only in S3 object metadata and never
  reads instruction files. This intentionally removes the instruction-file
  attack surface for GHSA-x8cp-jf6f-r4xh (CVE-2025-14761, Invisible Salamanders
  EDK replacement).
- Existing objects written with the instruction-file strategy cannot be read by
  this package.
- The `aws/aws-sdk-php` dependency lower bound of `^3.368` matches the patched
  version for this advisory.
- Decryption failures fail closed. This package never falls back to reading
  an unencrypted S3 object or returns ciphertext as plaintext.
- `security_profile = 'V3_AND_LEGACY'` is rejected during configuration because
  legacy V1/V2 formats lack key commitment and expose the GHSA-x8cp-jf6f-r4xh
  (CVE-2025-14761) attack surface. The AWS SDK warning for this profile also
  becomes an `ErrorException` under Laravel.
- `commitment_policy = 'FORBID_ENCRYPT_ALLOW_DECRYPT'` is rejected during
  configuration because it writes new objects without key commitment. Use
  `REQUIRE_ENCRYPT_ALLOW_DECRYPT` when legacy read compatibility is required;
  new writes remain key-committed.
- Legacy V1/V2 objects and objects written with the instruction-file strategy
  cannot be read by this package. For migration, read them with the AWS SDK
  directly and rewrite them using this package.
- `allow_decrypt_with_any_cmk = true` relaxes the fixed KMS key check and can
  weaken object provenance and key isolation.
- `encryption_context` is authenticated by KMS. Changing it makes existing
  objects with the previous context unreadable.
- Do not enable AWS SDK `debug` logging in production. HTTP dumps can contain
  encryption-envelope metadata.
- Never put plaintext, AWS credentials, KMS key material, or envelope values
  in logs or exception messages.
- Presigned GET and PUT URLs are disabled. A presigned GET would serve
  ciphertext without client-side decryption, and a presigned PUT could create
  a path for plaintext to reach S3 without CSE.

## Development

Run the complete test suite, style check, and static analysis with:

```sh
composer test
composer lint
composer analyse
```

`composer lint` runs Laravel Pint in test mode. `composer analyse` runs
PHPStan at level 6 against `src` and `tests`.

## License

MIT. See [LICENSE](LICENSE).
