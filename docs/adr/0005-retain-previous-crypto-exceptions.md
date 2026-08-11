# ADR 0005: Retain previous crypto exceptions

A reviewer proposed dropping the previous throwable from `UnableToReadFile` and
`UnableToWriteFile` so reporters could not reach an unsafe crypto error. That
does not establish the proposed guarantee: the outer exception is created inside
`EncryptedS3Adapter`, and its own trace records the caller's write arguments,
including plaintext. The plaintext is therefore reachable without walking the
previous chain.

The package retains the previous exception for debuggability and uses
`Support\SafeFailureReason` for the messages it constructs. PHP stack-trace
arguments are outside that boundary. Operators whose threat model includes
arguments in traces should set `zend.exception_ignore_args=On` in `php.ini`; this
removes arguments from every PHP stack trace and trades away argument context
application-wide. This is a generic Laravel/PHP write-path concern, not a
crypto-path behavior this package can selectively fix.
