# Changelog

All notable changes to this project are documented here.

## [Unreleased]

Initial stable release of a Laravel filesystem driver for AWS S3 Client-Side
Encryption V3. Cryptography is delegated to the AWS SDK.

### Fixed

- `response()`, `download()`, and `serve()` now send the plaintext `Content-Length`
  measured from the decrypted stream instead of the ciphertext size.

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

### Security

- Objects written with the AWS SDK instruction-file metadata strategy or with
  legacy V1/V2 envelopes cannot be read by this package.
