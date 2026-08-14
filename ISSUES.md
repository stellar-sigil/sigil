# Backlog

The work this repository intends to hand to contributors. Every row in the
Checks, Probes and Spec directives tables below maps to a row already committed
in [docs/CHECKS.md](docs/CHECKS.md), [docs/PROBES.md](docs/PROBES.md) or
[docs/SPEC.md](docs/SPEC.md). The Other table is the exception: those items have
no registry row yet, and each one needs its spec written before it becomes an
issue.

No issue is opened for code that is not yet in the tree. A row becomes an issue
once its stub, registry entry or failing test is committed, so a contributor
picking it up always has something concrete to point at.

## Point tiers

| tier | points | applies to |
|------|--------|------------|
| A | 400 | security-sensitive checks and live-network probes |
| B | 200 | spec directives, corpus pairs, adapters, report formats |
| C | 100 | documentation and CI |

## Checks

Each check is one file in `crates/sigil-test`, one corpus pair under `corpus/`,
and the two tests that prove it fires on the vulnerable half and stays silent on
the fixed half. `no_require_auth` (SIG-001) and `caller_not_owner` (SIG-002) are
the worked examples to copy.

| id | tier | status |
|----|------|--------|
| SIG-001 missing authorization | A | done |
| SIG-002 wrong authorizer | A | done |
| SIG-003 undeclared sub-invocation | A | done |
| SIG-004 declared sub-invocation never demanded | B | done (shares the `undeclared_transfer` corpus) |
| SIG-005 unauthorized caller succeeds | A | done |
| SIG-006 auth tree ordering | C | open |
| SIG-007 weak admin gate | A | open |
| SIG-008 ambiguous authorizer | A | open |
| SIG-009 unchecked try_auth result | A | open |
| SIG-010 contract self-authorizes a transfer | A | open |
| SIG-011 over-authorized view function | B | emits, but has no corpus pair and no test |
| SIG-012 authorization conditional on arguments | A | open |

## Probes

Each probe is the attempt that must fail plus the control that must succeed.
Requires testnet.

| id | tier | status |
|----|------|--------|
| PRB-001 nonce replay | A | open |
| PRB-002 expired signature | A | open |
| PRB-003 wrong signer | A | open |
| PRB-004 cross-network replay | A | open |
| PRB-005 custom account threshold | A | open |
| PRB-006 fee-bump does not launder auth | A | open |
| PRB-007 post-signing invocation tamper | A | open |
| PRB-008 archived state | A | open |

## Spec directives

Rows already documented in `docs/SPEC.md` with status `todo`.

| directive | tier |
|-----------|------|
| `expiration_max_ledgers` | B |
| `custom_account` | B |
| `any_of` | B |
| `forbid_authorizers` | B |

## Other

| item | tier |
|------|------|
| SARIF report output | B |
| JUnit report output | B |
| GitHub annotations output | B |
| Client-side conformance checks against a mock SEP-43 signer | B |
| One documentation page per check, with the vulnerable contract inline | C |

## Not padding

Documentation is capped at tier C and at one page per check that already
exists. If this backlog is ever short of work, the answer is more corpus pairs
and more probes, not more docs tickets.
