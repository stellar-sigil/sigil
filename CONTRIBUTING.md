# Contributing

## Ground rules

Every unit of work is a row in a registry before it is code. The registries are
[docs/CHECKS.md](docs/CHECKS.md) and [docs/PROBES.md](docs/PROBES.md). If you
want to add behaviour that has no row, open an issue proposing the row first.

A check is not finished when it passes. It is finished when it reports the
finding on the vulnerable half of its corpus pair and stays silent on the fixed
half. A test that would pass against broken code is not accepted.

A probe is not finished until both halves land: the attempt that must fail and
the control that must succeed. Without the control, an unrelated error reads as
a clean result.

## Scope of a pull request

One row, one pull request. Two rows in one branch will be asked to split, since
they are reviewed and merged independently.

## Before you push

    cargo fmt --all
    cargo clippy --all-targets -- -D warnings
    cargo test --all

## The fixtures are generated

Do not hand-edit anything in `fixtures/`. Regenerate:

    npm install --no-save @stellar/stellar-sdk
    node scripts/gen-fixtures.js > fixtures/auth_preimage_v1.json

CI regenerates and diffs these, so a hand-edit fails the build. The point is
that the Rust signing payload is checked against the JavaScript SDK rather than
against itself.

## Honesty about what works

This project asserts things about other people's contracts. A false positive
costs a stranger hours and costs the tool its credibility. Prefer reporting
`inconclusive` over guessing, and never describe a check as shipped in the
README before it is.
