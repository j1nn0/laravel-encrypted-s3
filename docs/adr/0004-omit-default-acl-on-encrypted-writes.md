# ADR 0004: Omit default ACLs on encrypted writes

Status: Superseded by [ADR 0008: No implicit ACLs on package-owned writes and copies](0008-no-implicit-acls-on-package-owned-writes-and-copies.md).

`EncryptedS3DiskFactory::make()` does not inject a default `ACL` into encrypted
put options. `Support\EncryptedS3Arguments::forPut()` adds an ACL only when a
disk or per-call Flysystem `Config` contains a non-empty `visibility` string.

S3 buckets created since April 2023 default to Object Ownership = `Bucket owner
enforced`, which disables ACLs. Sending `x-amz-acl: private` with `PutObject`
then fails with HTTP 400 `AccessControlListNotSupported`, while omitting the
ACL succeeds. Omitting an ACL cannot widen access: S3 objects are private by
default, and a canned `private` ACL grants nothing extra. The encrypted read
and write paths therefore omit the ACL by default, while explicit visibility
still opts in to the matching canned ACL.

This deliberately diverges from stock Laravel plus Flysystem. The upstream
`League\Flysystem\AwsS3V3\AwsS3V3Adapter::upload()` always resolves an ACL via
`determineAcl()`, whose default is `Visibility::PRIVATE`
(`vendor/league/flysystem-aws-s3-v3/AwsS3V3Adapter.php:140,154-159`). A stock
`s3` disk therefore also fails on ACL-disabled buckets. Only the encrypted
crypto path changes its default here.

The final scope decision in this ADR is superseded by ADR 0008. The package now
owns the `createDirectory()`, `copy()`, and `move()` paths so they follow the
no-implicit-ACL rule; `setVisibility()` remains delegated because it is an
explicit ACL operation.
