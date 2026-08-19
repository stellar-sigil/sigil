# Roadmap

Order is chosen so that each stage is useful on its own, and so that nothing
depends on a piece that has not been proven yet.

## Now: complete the sandbox checks

Five of twelve are implemented. The rest are specified in
[docs/CHECKS.md](docs/CHECKS.md) and each is one file plus a corpus pair.
Priority order is by what actually loses money: SIG-010 (a contract authorizing
transfers of user deposits as itself), SIG-007 (an admin gate any operator
satisfies), SIG-009 (a dropped `try_require_auth` result), then the rest.

## Next: the CLI

Today the checks are called from a contract's own test suite. That is the right
primary interface, since the assertions belong next to the tests that exercise
the contract. But it means Sigil cannot tell you anything about a contract you
have not written tests for.

`sigil check` will read `sigil.toml`, derive a draft spec from a compiled
`.wasm` contract spec, and report the surface it can determine statically.

## Then: live-network probes

Eight are specified in [docs/PROBES.md](docs/PROBES.md). They ask a different
question from the sandbox checks: not whether a contract demands the right
authorization, but whether the network rejects an entry that should not be
accepted. Nonce replay, expired signatures, wrong signer, cross-network replay.

These are gated on `crates/sigil-auth`, which is why the signing payload was the
first thing built and is pinned against the JavaScript SDK. A probe that
constructs its entry incorrectly reports a confident finding that is not real.

One caveat is already documented from experience: a probe must run with a
keystore holding only the identity it is impersonating, or the tooling signs on
the victim's behalf and the attempt succeeds for the wrong reason. See
[probes/README.md](probes/README.md).

## Later: the client side

A mock SEP-43 signer and a conformance suite for the application side, catching
an app that signs with the wrong network passphrase, signs an entry belonging to
another address, or submits one whose expiration ledger has passed.

## Not planned

Static analysis of contract source. Authorization is a runtime property of an
invocation tree, and a source-level approximation of it would produce exactly
the confident-but-wrong findings this project exists to avoid.
