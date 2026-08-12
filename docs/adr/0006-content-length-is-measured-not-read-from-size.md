# ADR 0006: Measure Content-Length from the decrypted stream

Laravel's `FilesystemAdapter::response()` uses `size()` for the
`Content-Length` header and then reads the file stream. On this package's disks,
`size()` intentionally delegates to S3 metadata and therefore reports the
ciphertext length, while `readStream()` returns decrypted plaintext. The two
lengths differ under the pinned AES-GCM V3 committing suite.

`EncryptedS3Filesystem::response()` therefore opens the decrypted stream before
building the response, measures its length with `fstat()`, and streams that same
handle from the callback. `Content-Length` is set only when the caller did not
provide one and the length was determinable. If the stream is unavailable or its
length cannot be determined, the header is omitted. Content type and disposition
remain Laravel's behavior, and `download()` and `serve()` inherit the override
through their existing `response()` calls.

Deriving plaintext length arithmetically as ciphertext length minus 16 was
rejected. Although the current suite stores a 16-byte GCM tag, that calculation
would be an unauthenticated assumption about an attacker-influenced object's
format. Measuring the authenticated decrypted body fails closed when tampering
causes decryption to fail, preserving the package's no-plaintext-on-failure
invariant.

The stream is opened exactly once. Re-reading it to measure the body would issue
another S3 `GetObject` and another KMS decryption for every response. The
already-open decrypted handle is therefore both the measurement source and the
streamed response body.
