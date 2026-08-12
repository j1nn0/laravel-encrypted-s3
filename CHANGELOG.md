# Changelog

All notable changes to this project are documented here.

## [Unreleased]

Initial stable release of a Laravel filesystem driver for AWS S3 Client-Side
Encryption V3. Cryptography is delegated to the AWS SDK.

### Fixed

- `response()`, `download()`, and `serve()` now send the plaintext `Content-Length`
  measured from the decrypted stream instead of the ciphertext size.

### Changed

- PHPStan analysis now runs with Larastan at level 10 over `src` and `tests`.

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

### Security

- Objects written with the AWS SDK instruction-file metadata strategy or with
  legacy V1/V2 envelopes cannot be read by this package.
- `read()` requires the decrypted response body to be a stream and fails closed
  otherwise, so a malformed response can no longer be returned to the caller as
  an empty string.
- AWS SDK plaintext buffers can spill to mode-`0600` local temp files at 2 MiB
  or larger; operators should place the configured temp directory on `tmpfs` or
  an encrypted volume because the package cannot prevent this.
