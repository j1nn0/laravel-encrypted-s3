# AGENTS.md

`j1nn0/laravel-encrypted-s3` adds an `encrypted-s3` Laravel filesystem driver backed by AWS S3
Client-Side Encryption V3. It is a security package: the invariants are the reason it exists, and a
change that quietly weakens one still looks correct on the diff.

## Read CLAUDE.md before changing anything

`CLAUDE.md` is the authority on this repo. Read it in full before you edit source, add a test, judge
whether a caller-supplied option is safe to forward, or decide what an operation is allowed to
report. It holds the layer-by-layer architecture, every security invariant and where each one is
enforced, and how the in-memory AWS backend the tests run against works.

`CONTEXT.md` defines the domain terms — use them. `docs/adr/` records decisions already settled;
read the relevant ADR before proposing a change to what it covers.

## One writer at a time

Investigation and implementation run as separate agents against one shared working tree and one git
index. Two agents writing at once corrupt each other's work.

- **Investigating** — run read-only. Report findings as precise `file.php:12-40` references and
  leave every file as you found it.
- **Implementing** — you are the only writer. Make the change, clear the verification gate, report.

Leave committing to the human. Changes are reviewed before they land.

## Verification gate

Report a task complete only once all three pass:

```sh
composer test      # PHPUnit; failOnRisky and failOnWarning are deliberate
composer lint      # Pint, laravel preset
composer analyse   # PHPStan + Larastan, level 6, over src and tests
```

A failing run is the answer, not an obstacle. Fix the cause in the implementation; the test and the
analysis config stay as they are.

## Security invariants hold by default

Treat every invariant in `CLAUDE.md` as fixed at its current strength. When the task as specified
would relax one, stop and report the conflict — that decision belongs to the human, and an
implementation that silently picks the weaker behaviour is the failure this package is built to
prevent.

Several invariants are enforced at two points on purpose. Before collapsing an apparent duplicate,
check whether it is one rule written twice (worth collapsing) or one rule with two enforcement
points (defence in depth — keep both).
