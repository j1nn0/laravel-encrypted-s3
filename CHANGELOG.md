# Changelog

All notable changes to this project are documented here.

## [Unreleased]

Initial stable release of a Laravel filesystem driver for AWS S3 Client-Side
Encryption V3. Cryptography is delegated to the AWS SDK.

### Fixed

- `response()`, `download()`, and `serve()` now send the plaintext `Content-Length`
  measured from the decrypted stream instead of the ciphertext size.
- `createDirectory()` failures are normalized to Flysystem's
  `UnableToCreateDirectory`, so Laravel disks with `throw => false` return `false`
  instead of leaking `UnableToWriteFile`.

### Changed

- PHPStan analysis now runs with Larastan at level 10 over `src` and `tests`.
- **Breaking change:** `copy()` and `move()` now use the package-owned S3
  server-side copy path. They no longer inherit source visibility or issue
  `GetObjectAcl`, and they send no implicit ACL; only an explicitly requested
  ACL is forwarded. `move()` deletes the source only after the copy succeeds.
- **Breaking change:** `createDirectory()` now writes its trailing-slash marker
  through the encrypted put path. The marker itself has a CSE V3 envelope and
  costs one KMS `GenerateDataKey` call; it no longer sends the upstream default
  `public-read` ACL.
- Copy `MetadataDirective` is pinned to `COPY`; caller-supplied values other
  than `COPY`, including `REPLACE`, are rejected so the CSE envelope cannot be
  discarded.

### Added

- Encrypted writes do not send a default ACL. `visibility` or an explicit
  `ACL` option is required to request one.
- `url()`, `temporaryUrl()`, and `temporaryUploadUrl()` always throw
  `UnsupportedOperationException` because presigned or public URLs would
  bypass client-side encryption or decryption.
- Unsupported and encryption-incompatible disk put options are rejected when
  the disk is constructed.
- `size()` returns the stored ciphertext size, not the plaintext size.
- Unknown keys under the `encryption` and `kms` configuration blocks are
  rejected at disk-construction time.
- Non-string top-level disk configuration keys are rejected at
  disk-construction time instead of being passed through to Flysystem.
- `symfony/http-foundation` is declared as a direct Composer dependency because
  the package imports `StreamedResponse` directly.

### Security

- Objects written with the AWS SDK instruction-file metadata strategy or with
  legacy V1/V2 envelopes cannot be read by this package.
- `copy()` and `move()` reject plaintext, V1, V2, mixed V2/V3, and incomplete
  envelope sources before creating a destination. A source must contain every
  CSE V3 envelope field and no V2 fields; the copied envelope and KMS encryption
  context are otherwise preserved without re-encryption.
- `read()` requires the decrypted response body to be a stream and fails closed
  otherwise, so a malformed response can no longer be returned to the caller as
  an empty string.
- AWS SDK plaintext buffers can spill to mode-`0600` local temp files at 2 MiB
  or larger; operators should place the configured temp directory on `tmpfs` or
  an encrypted volume because the package cannot prevent this.
