# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| 1.x | Yes |

## Reporting a vulnerability

Report vulnerabilities privately through GitHub's private vulnerability
reporting for this repository:
<https://github.com/j1nn0/laravel-encrypted-s3/security/advisories/new>.

The `aws/aws-sdk-php` `^3.368` lower bound is the patched version for
GHSA-x8cp-jf6f-r4xh (CVE-2025-14761). Downgrading that floor reintroduces the
advisory.
