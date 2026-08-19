# Security

## Reporting

Report a vulnerability in Sigil itself through GitHub's private vulnerability
reporting on this repository. Please do not open a public issue first.

## What counts as a vulnerability here

Sigil is a testing tool, so the serious failure is not a crash. It is a wrong
answer:

- A check that reports a finding on a correct contract. A false positive costs a
  stranger hours and costs the tool its credibility.
- A check that stays silent on a contract with the flaw it claims to catch.
- Any claim in the documentation that the code does not support.

All three are treated as security issues rather than ordinary bugs, because
users act on this tool's output when deciding whether a contract is safe.

## What Sigil does not do

It checks a contract against the surface you declare in `sigil.toml`. It cannot
tell you that the surface you declared is the right one. A spec that permits
something dangerous will pass.

It reasons about authorization only. It says nothing about arithmetic, storage
archival, reentrancy or economic design.

A clean run is evidence about one property, not a security audit.
