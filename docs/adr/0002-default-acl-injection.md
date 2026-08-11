# ADR 0002: Default ACL injection in the disk factory

Status: Superseded by [ADR 0004: Omit default ACLs on encrypted writes](0004-omit-default-acl-on-encrypted-writes.md).

The original decision was for `EncryptedS3DiskFactory::make()` to inject an
`ACL` into the default put options when the caller had not set one, derived
from the disk configuration's visibility. `Support\EncryptedS3Arguments::forPut()`
also derived `ACL` from the Flysystem `Config` for explicit disk or per-call
visibility. ADR 0004 reverses the factory injection so encrypted writes do not
send an ACL unless visibility is explicitly configured.
