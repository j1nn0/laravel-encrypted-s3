# ADR 0004: Omit default ACLs on encrypted writes

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

Delegated, non-encrypted operations retain upstream behavior. The wrapped
adapter's `createDirectory()`, `copy()`, and `setVisibility()` send ACLs and
fail with `AccessControlListNotSupported` on ACL-disabled buckets; `move()`
inherits the `copy()` limitation. `visibility()` reads `GetObjectAcl` and
continues to work because AWS returns the owner's full-control grant. Removing
these delegated ACLs would require reimplementing the upstream adapter, so it
is intentionally out of scope.
