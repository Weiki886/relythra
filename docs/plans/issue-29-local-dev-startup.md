# Issue #29 Local Development Startup

## Scope

Complete the existing no-Docker local startup entry point without changing API,
Worker, or Web behavior. Isolate each invocation's temporary binaries and logs,
preserve prior run data, and make the startup preflight's port-conflict behavior
regression-testable.

## Implementation

1. Add a shell integration test using temporary command shims and a temporary
   `TMPDIR`; verify a failed build does not remove a pre-existing run directory.
2. Replace the fixed shared run directory and recursive removal with a unique
   `mktemp` directory created only for normal startup.
3. Add a simulated occupied-port test that verifies startup exits before build
   and identifies the affected port. Add the test to `make check`.
4. Keep `--check` read-only apart from its existing PostgreSQL connectivity and
   database preparation behavior; it must not create runtime output directories.

## Verification

- Run the new shell regression test and `bash -n scripts/dev.sh`.
- Run `make check` and `git diff --check`.
- Do not start Docker or modify a real PostgreSQL database for the shell tests.

## Rollback

Revert this PR's isolated changes to the startup script, shell test, Makefile,
and this plan. No schema migration or persistent application data is involved.
