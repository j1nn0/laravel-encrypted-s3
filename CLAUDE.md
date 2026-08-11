# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

`j1nn0/laravel-encrypted-s3` is a standalone Composer package (no host app in this repo) that adds an
`encrypted-s3` Laravel filesystem driver backed by AWS S3 Client-Side Encryption V3. All crypto is
delegated to the AWS SDK (`S3EncryptionClientV3` + `KmsMaterialsProviderV3`); this package never
implements ciphers itself.

## Commands

```sh
composer test                                   # PHPUnit 11, 12, or 13, whole suite
vendor/bin/phpunit --filter test_put_and_get_round_trip_plaintext   # single test
vendor/bin/phpunit tests/Feature/EncryptedS3FilesystemTest.php      # single file
composer lint                                   # Pint (laravel preset) in --test mode
vendor/bin/pint                                 # apply style fixes
composer analyse                                # PHPStan with Larastan, level 6 over src + tests
```

PHPUnit runs with `failOnRisky` and `failOnWarning` — an E_USER_WARNING from the AWS SDK fails the
suite, which is deliberate (see the `V3_AND_LEGACY` rejection below).

## Architecture

Four layers, wired top-down by `EncryptedS3DiskFactory::make()`:

1. `EncryptedS3ServiceProvider` — `Storage::extend('encrypted-s3', …)`, auto-discovered via
   `composer.json` `extra.laravel.providers`.
2. `EncryptedS3DiskFactory` — wiring only: `Support\DiskConfiguration` validates the disk config,
   while `Support\AwsClientSettings` derives the `S3Client` + `KmsClient` settings (KMS region and
   credentials fall back to the disk's). The factory assembles the stack and passes the raw disk
   config through to Laravel/Flysystem. Config errors throw `InvalidConfigurationException` at
   disk-construction time, not on first I/O.
3. `Flysystem\EncryptedS3Adapter` — the split point. `read`/`readStream`/`write`/`writeStream` go
   through `S3EncryptionClientV3`; **everything else delegates to a wrapped `AwsS3V3Adapter`**
   (`$this->inner`). That is why `fileSize()` reports ciphertext size and `mimeType()` reports
   unencrypted S3 metadata. The adapter itself builds no request arguments — it holds three
   constructor arguments (`S3EncryptionClientV3`, `AwsS3V3Adapter`, `EncryptedS3Arguments`) and
   routes.
4. `Filesystem\EncryptedS3Filesystem` — extends Laravel's `FilesystemAdapter` only to make
   `url`/`temporaryUrl`/`temporaryUploadUrl` throw `UnsupportedOperationException` and report
   `providesTemporary*Urls() === false`.

`Support\ObjectLocation` (`@internal`) owns the bucket and raw root in one place. The delegated
adapter receives `bucket()` and `root()` from it, while `Support\EncryptedS3Arguments` uses its
`key()` method, so encrypted and delegated paths derive from the same object location. Because the
delegated adapter constructs its own `PathPrefixer`, `ObjectLocation` keeps a separate one for
encrypted keys. `EncryptedS3Arguments` is the single place SDK request arguments are built:
`forPut()` and `forGet()` share one private `commonArguments()`, so the six arguments both requests
need — including the `@MetadataStrategy` pin — are written once.

`Support\EncryptionOptions` is the config value object; it validates in the constructor so an
invalid commitment policy, security profile, or encryption context can never reach the SDK.

## Security invariants (do not relax without an explicit request)

These are the point of the package. Several are enforced in more than one place; keep them in sync.

- **Metadata strategy is pinned to `HeadersMetadataStrategy::class`** on every put and get, in
  `EncryptedS3Arguments::commonArguments()`. The instruction-file strategy is never used or read —
  this is the mitigation for GHSA-x8cp-jf6f-r4xh (CVE-2025-14761, Invisible Salamanders EDK
  replacement), and it also means objects written with instruction files are unreadable by design.
  The two pins are not equally load-bearing; `docs/adr/0001-metadata-strategy-pins.md` records why
  neither may be dropped.
- **`FORBID_ENCRYPT_ALLOW_DECRYPT` and `V3_AND_LEGACY` are rejected** in `EncryptionOptions`, with
  the security rationale in the exception message. Only `REQUIRE_ENCRYPT_*` policies and profile
  `V3` are accepted. The `aws/aws-sdk-php: ^3.368` lower bound is the patched advisory version.
- **No unencrypted fallback anywhere.** `kms.key_id` is required; decryption failures surface as
  `UnableToReadFile` and never return ciphertext or an unencrypted object as plaintext.
- **No presigned URLs**, GET or PUT — either would bypass client-side crypto in one direction.
- **Reserved put options.** `Metadata`, `Body`, `Bucket`, `Key`, and any `@`-prefixed key are
  reserved. `PutOptions::isReserved()` is the single definition of that rule; the two enforcement
  points remain deliberate defence in depth — `PutOptions::validated()` rejects at config time,
  `PutOptions::filtered()` strips again at request time.
  Surviving keys must be in `AwsS3V3Adapter::AVAILABLE_OPTIONS` (checked at request time only).
  Reserved encryption-context keys: `aws:x-amz-cek-alg`, `kms_cmk_id`.
- **Never let plaintext, credentials, KMS key material, or envelope values reach an exception
  message or log.** `EncryptedS3Adapter::exceptionReason()` deliberately reduces a throwable to its
  short class name plus an AWS error code.

## Testing approach

`tests/Support/InMemoryAws.php` is a hand-written in-memory S3 + KMS backend supplied through the
AWS SDK `handler` config key (the disk config in `TestCase::diskConfig()` passes
`handler` / `kms.handler`). It returns a fixed data key and ciphertext blob, so the *real* SDK crypto
path runs end-to-end while remaining deterministic, and it records `s3Requests` / `kmsRequests` so
tests can assert on the wire bytes — e.g. that plaintext never appears in a PutObject body.

Use `TestCase::configureDisk([...])` to override disk config within a test; it deep-merges over the
default config and forgets the cached disk. Security behaviors are tested by staging a hostile
object with `InMemoryAws::putRaw()` (tampered ciphertext, V2 envelope, instruction file, no
envelope) and asserting the read fails closed.

When adding a supported operation, also add its row to the support matrix in `README.md` — the table
documents which operations are constrained by encryption and why.
