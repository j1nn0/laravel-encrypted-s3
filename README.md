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

The CSE V3 implementation is provided by AWS SDK for PHP 3.382.2 or newer.

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

Unknown keys under the `encryption` and `kms` blocks are rejected at
disk-construction time. This is deliberate: typos in security-relevant
settings fail loudly rather than silently falling back to a default.

These optional AWS SDK client settings are forwarded — `endpoint`,
`use_path_style_endpoint`, `retries`, `http`, `http_handler`, `handler`, and
`debug`. Anything else in the disk configuration is ignored rather than passed
to the SDK. The common settings may be set under `kms` for the KMS client;
`use_path_style_endpoint` is S3-only and is rejected under `kms`, and these
common settings are never inherited from the disk. Region and credentials are the exception: the KMS
client inherits both from the disk when they are not set under `kms`. A
`credentials` array takes precedence over `key`, `secret`, and `token` at the
same level.

Only Laravel's Flysystem write-default keys — `visibility`,
`directory_visibility`, `retain_visibility`, `disable_asserts`, `url`, and
`temporary_url` — are forwarded as Flysystem defaults. AWS PutObject
parameters placed at the top level of the disk configuration are ignored;
`options` is the only disk-level route for them, while per-call Flysystem
`Config` remains the other route.

`root` is an S3 key prefix. Encrypted writes, directory markers, and server-side
copies send no canned ACL unless the user asks for one through `visibility`,
`directory_visibility` for `makeDirectory()`, or an explicit `ACL` option.
Per-call Flysystem `Config` options override the disk-level `options` array. If
both are set, `visibility` is applied afterwards and wins over an explicit
`ACL`. `copy` and `move` do not retain source visibility and do not issue
`GetObjectAcl`. Before copying, they require the source metadata to contain a
complete CSE V3 envelope and no V2 envelope fields; non-CSE sources are rejected
before a destination is created. An explicit `MetadataDirective` other than
`COPY` is rejected so the CSE envelope metadata cannot be discarded. Each copy
performs one validation `HeadObject` in addition to the SDK copy strategy's
`HeadObject`.
`options['ACL']` is the route for canned ACLs that Flysystem visibility cannot
express, such as `bucket-owner-full-control`. Explicit ACLs can fail on
ACL-disabled buckets, so omit them when using Object Ownership
`BucketOwnerEnforced`. `throw` retains Laravel's normal filesystem exception
behavior.
`options` is filtered to this package's CSE-compatible `PutObject` allowlist:
`ACL`, `CacheControl`, `ContentDisposition`, `ContentEncoding`, `ContentType`,
`Expires`, `GrantFullControl`, `GrantRead`, `GrantReadACP`, `GrantWriteACP`,
`RequestPayer`, `StorageClass`, `Tagging`, `WebsiteRedirectLocation`, and
`ChecksumAlgorithm`. `Metadata`, `Body`, `Bucket`, `Key`, and keys beginning
with `@` are reserved and rejected or omitted. `ContentLength`,
`MetadataDirective`, `CopySourceSSECustomerAlgorithm`,
`CopySourceSSECustomerKey`, and `CopySourceSSECustomerKeyMD5` are rejected
because the first contradicts the ciphertext body and the others are
CopyObject-only. `ServerSideEncryption`, `SSEKMSKeyId`,
`SSECustomerAlgorithm`, `SSECustomerKey`, and `SSECustomerKeyMD5` are rejected
because server-side encryption is out of scope for CSE, and SSE-C would make
objects unreadable through this package. The upstream Flysystem option constant
is used only as a test tripwire, not as this allowlist. Disk `options` outside
this allowlist are rejected at configuration time to catch mistakes; per-call
runtime `Config` is broader because it also carries Laravel/Flysystem keys such
as `visibility` and `mimetype`, so unsupported keys are silently stripped there.
`ACL` cannot be combined with `GrantFullControl`, `GrantRead`, `GrantReadACP`,
or `GrantWriteACP`. The PutObject reference is silent on this combination, but
the SDK does not validate it and reported S3 responses reject it with `InvalidRequest`, so
both configuration validation and final request assembly reject it early.
Grant options remain valid on their own.

The package sends a canned `x-amz-acl` only when the user explicitly requests
one through `visibility`, `directory_visibility`, or `options['ACL']`. Explicit
grant options are likewise sent only when configured. `makeDirectory()` writes
an encrypted trailing-slash marker through the CSE put path and makes one KMS
`GenerateDataKey` call per marker. `copy()` and `move()` use server-side S3
copy without retaining source visibility; `MetadataDirective` is pinned to
`COPY`, and an explicit `REPLACE` is rejected. `visibility()` reads the object
ACL and works on ACL-disabled buckets because AWS returns the owner's
full-control grant. `setVisibility()` remains an explicit ACL operation and
can fail with `AccessControlListNotSupported` when ACLs are disabled.

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

`EncryptionOptions` exposes the configuration values as typo-safe constants:
`COMMITMENT_POLICY_FORBID_ENCRYPT_ALLOW_DECRYPT`,
`COMMITMENT_POLICY_REQUIRE_ENCRYPT_ALLOW_DECRYPT`,
`COMMITMENT_POLICY_REQUIRE_ENCRYPT_REQUIRE_DECRYPT`, `SECURITY_PROFILE_V3`, and
`SECURITY_PROFILE_V3_AND_LEGACY`. The first and last are retained for SDK
compatibility but rejected during configuration; only the two
`REQUIRE_ENCRYPT_*` policies and `V3` are accepted.

## Required IAM permissions

The application credentials need, at minimum:

- `kms:GenerateDataKey` for the configured KMS key
- `kms:Decrypt` for the configured KMS key
- `s3:PutObject`
- `s3:GetObject`
- `s3:DeleteObject`
- `s3:ListBucket`
- `s3:GetObjectAcl` and `s3:PutObjectAcl` (for visibility operations)

The package's server-side `copy` and `move` use one `HeadObject` to verify the
source CSE V3 envelope, and the SDK uses another `HeadObject` to select the
copy strategy. `HeadObject` uses the `s3:GetObject` permission. They then use
`s3:GetObject` on the source and `s3:PutObject` on the destination; there is no
separate `s3:CopyObject` IAM action.

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
| `put` / `write` | Supported with constraints | Stored encrypted with CSE. No ACL is sent unless requested through `visibility` or an explicit `options['ACL']`; `visibility` wins when both are set. String bodies are buffered by the SDK and can spill plaintext to a local `php://temp` file at 2 MiB or larger; watch `memory_limit` and the temp-file guidance below. |
| `get` / `read` | Supported with constraints | Returns decrypted plaintext. The complete ciphertext and plaintext are buffered by the SDK, and plaintext at 2 MiB or larger can spill to a local `php://temp` file. |
| `writeStream` | Supported with constraints | Works, but is not memory-efficient because the SDK CSE implementation is non-streaming. A caller-supplied resource is wrapped as-is, so the SDK does not create an additional plaintext temp-file copy; any spill belongs to the caller's stream. |
| `readStream` | Supported with constraints | The returned resource is backed by decrypted plaintext that the SDK may spill to a local `php://temp` file at 2 MiB or larger. The resource is detached, so callers must close it. |
| `download` / `response` / `serve` | Supported with constraints | Streams decrypted plaintext. `Content-Length` is measured from the authenticated decrypted stream, and `download()` and `serve()` route through `response()`; the same stream is measured and sent, so one S3 GET serves a response. |
| `exists` / `fileExists` / `directoryExists` | Fully supported | Unrelated to encryption. |
| `delete` / `deleteDirectory` | Fully supported | Unrelated to encryption. |
| `makeDirectory` / `createDirectory` | Supported with constraints | Writes a CSE-encrypted trailing-slash marker through the put path. It sends no ACL by default, makes one KMS `GenerateDataKey` call, and accepts an explicitly configured `visibility` or `directory_visibility`. |
| `copy` | Supported with constraints | Uses SDK server-side copy, preserving the encryption envelope and original KMS encryption context without re-encryption. It first verifies that the source has every CSE V3 envelope field and no V2 field; non-CSE sources are rejected before the destination is created. It sends no ACL or `GetObjectAcl` request unless an ACL is explicitly requested; `MetadataDirective` is fixed to `COPY`, and `REPLACE` is rejected. |
| `move` | Supported with constraints | Copy followed by delete. The same CSE V3 source-envelope check and ACL/metadata-directive rules as `copy` apply; the source is deleted only after a validated copy succeeds. |
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

## Not supported

- Large uploads through `S3EncryptionMultipartUploaderV3`
- Instruction-file metadata strategy (intentionally disabled; only S3 object metadata is used)
- `@CipherOptions['Aad']`
- V1 or V2 format writes and legacy-format reads
- Re-encryption or key-rotation utilities
- Custom plaintext-size metadata
- Application-level control over the AWS SDK's plaintext `php://temp` spill behavior
- Combined SSE server-side encryption support

## Constraints and security notes

- CSE V3 is non-streaming. Encryption and decryption can require several
  times the plaintext size in memory, and the SDK's string-buffer paths can
  also spill plaintext to a local temp file at 2 MiB (2,097,152 bytes) or
  larger.
- The affected operations are string-based `put()`/`write()`, decrypted
  `get()`/`read()` and `readStream()`, and `response()`/`download()`/`serve()`
  through their decrypted stream. Below 2 MiB, `php://temp` remains memory-only;
  at or above 2 MiB, it can create a mode-`0600` file in `sys_get_temp_dir()`.
  The file has a real name while open, although stream metadata still reports
  `php://temp`.
- The temp file is normally unlinked when its stream closes. The resource from
  `readStream()` is detached, so callers must close it; abnormal termination
  such as `SIGKILL`, an OOM kill, or a segfault can leave the plaintext file
  behind. A `writeStream()` resource is caller-owned and does not receive an
  additional SDK-created plaintext temp-file copy.
- There is no package-level control for this SDK buffer. Point `sys_temp_dir`
  in `php.ini`, or set `TMPDIR`/`TMP`/`TEMP` before process startup, at a
  RAM-backed `tmpfs` or encrypted volume. A runtime `putenv()` change is too
  late because the temp-directory value is cached at startup.
- `size()` is ciphertext size.
- `checksum()` is a plaintext hash and requires download, KMS decryption, and
  the associated memory and network cost.
- MIME type, object key names, and object size are not encrypted.
- `copy` and `move` preserve the existing envelope and do not re-encrypt.
- `copy` and `move` fail closed for plaintext, V1, V2, mixed V2/V3, or incomplete
  CSE metadata. The source must have all V3 envelope fields and no V2 fields;
  the `x-amz-d` value is only checked for presence. The validation adds one
  `HeadObject` per copy in addition to the SDK's strategy-selection request.
- `makeDirectory()` stores its marker with a CSE V3 envelope and performs one
  KMS `GenerateDataKey` call per invocation.
- `copy()` rejects `MetadataDirective=REPLACE`; the directive is pinned to
  `COPY` so the CSE envelope metadata remains attached to the copied object.
- Package-owned writes and copies omit an implicit canned ACL. Only an explicit
  ACL request is sent; `setVisibility()` is intentionally an explicit ACL
  operation.
- This package stores encryption envelopes only in S3 object metadata and never
  reads instruction files. This intentionally removes the instruction-file
  attack surface for GHSA-x8cp-jf6f-r4xh (CVE-2025-14761, Invisible Salamanders
  EDK replacement).
- Existing objects written with the instruction-file strategy cannot be read by
  this package.
- The `aws/aws-sdk-php` dependency requires `^3.382.2`. AWS SDK 3.368 fixed
  GHSA-x8cp-jf6f-r4xh (CVE-2025-14761); 3.382.2 is required because its S3 REST
  serializer is the first version that omits a header when the package passes a
  null ACL to `S3Client::copy()`.
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
- Failure messages constructed by this package are redacted; PHP stack-trace
  arguments are outside this boundary and can contain caller arguments such as
  plaintext.
- If your threat model includes plaintext in logs, set
  `zend.exception_ignore_args=On` in `php.ini`. This removes arguments from
  every PHP stack trace and trades away argument context application-wide; it is
  a generic Laravel/PHP write-path concern, not specific to this package.
- Presigned GET and PUT URLs are disabled. A presigned GET would serve
  ciphertext without client-side decryption, and a presigned PUT could create
  a path for plaintext to reach S3 without CSE.

## Versioning and support policy

From 1.0.0 onward, this package follows Semantic Versioning. The public API is
`EncryptedS3ServiceProvider`, `EncryptedS3DiskFactory`,
`Filesystem\EncryptedS3Filesystem`, `Support\EncryptionOptions`,
`Exceptions\InvalidConfigurationException`,
`Exceptions\UnsupportedOperationException`, and the disk configuration array
shape. Everything marked `@internal` — all `Support\*` classes except
`EncryptionOptions`, plus `Flysystem\EncryptedS3Adapter` — is outside the
compatibility promise and may change in any release. New Laravel and PHP
versions are added in minor releases; support for old versions is dropped only
in a major release.

## Development

Run the default Unit + Feature suite, style check, and static analysis with:

```sh
composer test
composer lint
composer analyse
```

`composer lint` runs Laravel Pint in test mode. `composer analyse` runs
PHPStan at level 10 against `src` and `tests`.

The HTTP integration layer uses the pinned `motoserver/moto:5.2.2` container
as local S3 + KMS. Start it, run the explicit integration suite, and stop it
with:

```sh
docker compose up -d --wait
composer test:integration
docker compose down -v
```

The fast Unit + Feature suite uses the unchanged `InMemoryAws` backend and
does not need Moto. Moto is a mock, so these integration results do not prove
compatibility with real AWS S3/KMS; real AWS remains authoritative.

## License

MIT. See [LICENSE](LICENSE).
