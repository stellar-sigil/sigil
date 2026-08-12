# Probe registry

Probes run against a live network. Each one submits a real signed transaction
and asserts the network's response, so a probe cannot pass by construction the
way a sandbox assertion can.

Every probe is defined as a pair: the attempt that must FAIL, and the control
that must SUCCEED. A probe reporting a failure without its passing control is
treated as inconclusive, because an unrelated error would otherwise read as a
clean result.

Status: `done` shipped, `wip` in progress, `todo` not started.

| id | title | must fail | control | status |
|----|-------|-----------|---------|--------|
| PRB-001 | Nonce replay | resubmit an accepted auth entry unchanged | same invocation with a fresh nonce | todo |
| PRB-002 | Expired signature | `signature_expiration_ledger` in the past | same entry, future expiration | todo |
| PRB-003 | Wrong signer | entry for address A signed by keypair B | entry for A signed by A | todo |
| PRB-004 | Cross-network replay | entry signed with the pubnet passphrase, submitted to testnet | entry signed with the testnet passphrase | todo |
| PRB-005 | Custom account threshold | 1-of-3 signatures against a 2-of-3 `__check_auth` | 2-of-3 signatures | todo |
| PRB-006 | Fee-bump does not launder auth | fee-bump wrapping an inner tx whose auth entry is unsigned | same fee bump, inner entry signed | todo |
| PRB-007 | Invocation tamper | signed entry whose invocation args are edited after signing | unedited entry | todo |
| PRB-008 | Archived state | invoke against an archived auth-nonce entry | invoke after restore | todo |

## Preconditions

PRB-001 depends on the nonce being a real ledger entry rather than contract
state. PRB-005 needs a deployed `__check_auth` custom account; the fixture for
it lives in the corpus rather than being generated per run.

PRB-008 is listed last because archival behaviour is the most likely of these to
change between protocol versions. Pin the protocol version in the report.

## Signing

All probes build their signature over
`SHA-256(XDR(HashIDPreimage::SorobanAuthorization))`, implemented in
`crates/sigil-auth` and pinned against a JS SDK fixture. If that fixture ever
fails, every probe result in this file is void.
