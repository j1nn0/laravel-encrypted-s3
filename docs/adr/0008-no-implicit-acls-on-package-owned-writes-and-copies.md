# ADR 0008: No implicit ACLs on package-owned writes and copies

Status: Accepted. Supersedes [ADR 0004: Omit default ACLs on encrypted writes](0004-omit-default-acl-on-encrypted-writes.md).

## Context

ADR 0004 correctly removed the default ACL from encrypted put requests, but it
treated the remaining delegated operations as only an availability concern:
ACL-disabled buckets reject requests that contain ACL headers. It missed a more
serious confidentiality issue. Flysystem's
`PortableVisibilityConverter` defaults directory visibility to `Visibility::PUBLIC`,
so the delegated `createDirectory()` path sent `x-amz-acl: public-read`. On an
ACL-enabled bucket this silently created a world-readable, zero-byte directory
marker from a package whose purpose is confidentiality. The behavior was
confirmed with an actual request trace.

ADR 0004 also assumed that removing those delegated ACLs required reimplementing
the upstream adapter. That assumption was too broad. `createDirectory()` can
reuse the existing encrypted put path with a trailing-slash key and an empty
body. `copy()` and `move()` can use the raw S3 client's `copy()` method with a
null ACL. The SDK's `ObjectCopier` continues to provide `HeadObject` size
detection, the 5 GiB multipart threshold, multipart `UploadPartCopy`, and
correct `CopySource` encoding, including spaces and plus signs.

## Decision

- `createDirectory()` writes its trailing-slash marker through the encrypted
  put path. It uses `directory_visibility` only when explicitly supplied, and
  never supplies a default visibility.
- `copy()` calls the raw `S3Client::copy()` path. An explicit `visibility` or
  `ACL` option supplies the ACL argument; otherwise the argument is `null`.
  `Aws\Api\Serializer\RestSerializer::applyHeader()` skips null header
  values, so the request contains no `x-amz-acl` header. This null-header
  behavior first exists in `aws/aws-sdk-php` 3.382.2, so the package's lower
  bound is pinned there; 3.368 remains the minimum version that fixes the
  GHSA-x8cp-jf6f-r4xh advisory but does not provide this copy guarantee.
  `retain_visibility` is intentionally not used, so the copy destination
  receives the bucket default (normally private) and no `GetObjectAcl` request
  is made.
- `move()` remains copy followed by delete. The source is deleted only after
  the copy succeeds.
- `MetadataDirective` is pinned to `COPY`. A caller-supplied value other than
  `COPY`, including `REPLACE`, is rejected with `InvalidConfigurationException`
  rather than silently overridden. `REPLACE` would omit the source user
  metadata and silently remove the CSE V3 envelope, leaving an unreadable
  destination. This is the copy equivalent of the `@MetadataStrategy` pin.
- `setVisibility()` remains delegated. It is an explicit user request to send
  an ACL, so failure on an ACL-disabled bucket is correct.
- Copy and move failures are wrapped in Flysystem's `UnableToCopyFile` and
  `UnableToMoveFile` with the reason produced by `Support\SafeFailureReason::from()`.
  `because()` on these Flysystem exceptions does not accept a `$previous`
  exception, so the redacted reason remains in the message but the exception
  chain is not retained, unlike the read and write paths.

## Consequences

Every object created by this package's encrypted put and directory paths has a
CSE V3 envelope. A directory marker costs one KMS `GenerateDataKey` call per
`makeDirectory()` invocation. This is accepted because directory creation is
low frequency and S3 does not require directory markers.

Server-side copies retain the original ciphertext, CSE envelope, and KMS
encryption context; they do not re-encrypt. Unrequested ACLs are omitted, which
works with ACL-disabled buckets and avoids making a public marker or copy on an
ACL-enabled bucket. Explicit ACL requests remain the caller's responsibility.
