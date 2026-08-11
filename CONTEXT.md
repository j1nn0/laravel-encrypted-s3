# Encrypted S3 Filesystem

Terms used for filesystem operations backed by S3 objects that are encrypted before they leave the
application. The language here names the distinction between operations that touch ciphertext and
operations that do not.

## Language

**Crypto path**:
The route taken by filesystem operations whose payload is encrypted or decrypted in the application.
Reading and writing object contents belong to it.
_Avoid_: encryption pipeline, secure path

**Delegated path**:
The route taken by filesystem operations that never touch object contents and are served by the
underlying S3 filesystem unchanged. Listing, existence, size, and visibility belong to it.
_Avoid_: passthrough, fallback path

**Split point**:
The place where a single filesystem decides whether an operation belongs to the crypto path or the
delegated path.
_Avoid_: boundary, dispatch layer

**Request arguments**:
The set of values describing one encrypted object operation to the AWS SDK. Some are shared by reads
and writes, others are specific to one of them.
_Avoid_: parameters, payload, options

**Reserved put option**:
A write option owned by the crypto path, which a caller may never supply. Distinct from the S3 write
options a caller is free to set.
_Avoid_: forbidden option, blocked parameter

**Metadata strategy pin**:
The commitment that encrypted metadata is always carried in object headers, rather than the strategy
being chosen per request.
_Avoid_: header mode, metadata configuration

**Envelope**:
The encrypted data key and accompanying material stored with an object, without which the object
cannot be decrypted.
_Avoid_: wrapper, header blob
