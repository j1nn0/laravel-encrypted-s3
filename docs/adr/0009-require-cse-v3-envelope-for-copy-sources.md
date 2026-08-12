# ADR 0009: Require a CSE V3 envelope for copy sources

Status: Accepted.

## Context

`EncryptedS3Adapter::copy()` uses S3 server-side copy, so the source ciphertext
and metadata are copied without passing the object through the encryption
client. Before this decision, the adapter did not verify that the source was a
CSE object. A plaintext object placed in the bucket through another path could
therefore be copied successfully, producing a plaintext destination on an
encrypted disk. This was confirmed with an actual request trace and contradicted
the README contract that copies preserve the encryption envelope.

## Decision

Fail closed before issuing the copy request. After `forCopy()` resolves the
bucket and root-prefixed source key, the adapter issues `HeadObject` and passes
the returned metadata to `EncryptedS3Arguments::assertCopySourceIsEncrypted()`.
The source is accepted only when both conditions hold:

- every field returned by `Aws\Crypto\MetadataEnvelope::getV3Fields()` is
  present; and
- no field returned by `MetadataEnvelope::getV2Fields()` is present.

The metadata keys are normalized to lower case before the checks. The AWS SDK's
`MetadataEnvelope` is the only source of the field definitions; this package
does not maintain a second list of envelope key strings. The V2 exclusion is
intentional: the V3 read path enters the V3 branch and then rejects V2 fields
through `DecryptionTraitV3::checkEnvelopeForExclusiveMapKeys()`. Copy validation
must not create a destination that the read path cannot decrypt.

`x-amz-d` is checked for presence only. Verifying its value would require KMS
`Decrypt` and key-commitment re-derivation, which is outside the responsibility
of a server-side copy validation. The AWS SDK remains responsible for the
cryptographic checks during decryption.

Validation failures raise a fixed, non-sensitive reason in
`UnableToCopyFile`. A `move()` deletes the source only after this validation and
the copy succeed, so a rejected source remains in place. Failures from
`HeadObject` continue to use `SafeFailureReason::from()` before being exposed in
the Flysystem exception.

## Consequences

The package cannot copy plaintext, V1, V2, mixed V2/V3, or incomplete-envelope
sources. This is a deliberate compatibility restriction in exchange for the
package's fail-closed security invariant.

Each copy performs two `HeadObject` requests: one owned by this package for the
envelope check and one issued by the AWS SDK's `ObjectCopier` for size-based
strategy selection. This additional request is accepted. Reimplementing the
SDK's 5 GiB threshold, multipart `UploadPartCopy` handling, and `CopySource`
encoding in order to share one `HeadObject` would add complexity and risk for a
low-value optimization.

The alternative of documenting that callers are responsible for ensuring that
copy sources are encrypted was rejected. A security package should prevent a
successful operation from silently violating its encryption contract when it
can cheaply establish the required envelope before creating the destination.
