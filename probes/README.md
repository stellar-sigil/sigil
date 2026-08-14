# Live-network probes

The registry is [../docs/PROBES.md](../docs/PROBES.md). This file records what
has actually been run on a network, and one harness requirement that is easy to
get wrong.

## Deployed target

`probes/auth_target` on Stellar **testnet**:

| | |
|---|---|
| contract | `CCFEP5YJV6FG2S2WCPUZWWI2E2DOF3URKQRVVQKOLPOQF74AIP5754VA` |
| deploy tx | `a5fa7e5b91733fa68a1e751e9f061407337cc4932e4e7cf6f65d5fbdf15bb3b0` |
| control tx | `303078742523d2415d188e142a3b0b7b44986683061d5fc5eb7efdc2773183a9` |
| the false positive | `11b3261ef9c90f87e66ec2937b89310c1626dd317f6014b43af5e2e02f76c114` |

The control transaction is the owner authorizing `set_value` for its own
address, which is the half of every probe that must succeed. Explorer:
`https://stellar.expert/explorer/testnet/tx/<hash>`.

## The harness must not hold the victim's key

Running the PRB-003 attempt (sign for address A with keypair B) from a normal
developer machine produced a **false positive**: the transaction succeeded and
wrote the owner's state, which reads as a network vulnerability and is not one.
That transaction is `11b3261e...` in the table above, kept deliberately.

The network was not at fault. `stellar contract invoke` resolves the auth
entries that simulation reports and signs them with any matching key in the
local keystore. The owner's key was in that keystore, so the tooling signed on
the owner's behalf, and the attempt that was supposed to be impossible sailed
through. The transaction envelope still showed a single signature, because
Soroban authorization signatures live inside the operation rather than in the
envelope's signature list, so a casual look at the envelope does not reveal it
either.

With a keystore containing only the attacker's key, the same command fails
before it reaches the network:

    error: Missing signing key for account GBJHB53K...

Both outcomes are wrong for a probe. The first is the harness authorizing as
the victim; the second is the client refusing to build the transaction, which
is a local failure rather than the network rejecting anything.

**A probe that only shows a client-side error has not tested the network.** The
real PRB-003 has to construct the authorization entry directly, sign it with
the wrong key, submit it, and assert the network's rejection. That is what
`crates/sigil-auth` exists for, and it is why the signing payload was built and
pinned against the JS SDK before any probe was attempted.

Status: PRB-003 is **not implemented**. The target contract is deployed, the
control half passes, and the requirement above is now a precondition in the
registry.

## Reproducing

    cargo build --target wasm32v1-none --release -p probe-auth-target
    stellar contract deploy \
      --wasm target/wasm32v1-none/release/probe_auth_target.wasm \
      --source <key> --rpc-url <rpc> --network-passphrase "Test SDF Network ; September 2015"

Note `wasm32v1-none`, not `wasm32-unknown-unknown`. Soroban rejects the latter
on Rust 1.82+ because it enables reference-types and multi-value.
