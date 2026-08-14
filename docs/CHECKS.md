# Check registry

Checks that run in the `soroban-sdk` test environment. No network needed.

Each check compares the authorization tree a contract actually demands
(`env.auths()`) against the tree declared in `sigil.toml`. A check is only
accepted once it reports the finding on the vulnerable half of a corpus pair
and stays silent on the fixed half.

Status: `done` shipped, `wip` in progress, `todo` not started.

| id | title | severity | corpus pair | status |
|----|-------|----------|-------------|--------|
| SIG-001 | State-changing function requires no authorization | critical | `no_require_auth` | done |
| SIG-002 | Authorization demanded from the caller instead of the owning address | critical | `caller_not_owner` | done |
| SIG-003 | Auth tree contains a sub-invocation the spec does not declare | high | `undeclared_transfer` | done |
| SIG-004 | Declared sub-invocation is never demanded | medium | `undeclared_transfer` | done |
| SIG-005 | Unauthorized caller succeeds against a restricted function | critical | `open_admin_fn` | todo |
| SIG-006 | Auth tree shape matches but ordering diverges from the spec | low | `reordered_tree` | todo |
| SIG-007 | Admin-only function is authorizable by a non-admin address | critical | `weak_admin_gate` | todo |
| SIG-008 | Two addresses can satisfy a rule that names one | high | `ambiguous_authorizer` | todo |
| SIG-009 | Authorization is demanded but the result is not checked | high | `unchecked_try_auth` | todo |
| SIG-010 | Token transfer authorized by the contract rather than the holder | critical | `contract_self_auth` | todo |
| SIG-011 | Read-only function demands authorization | low | `over_auth_view` | wip |
| SIG-012 | Auth requirement depends on argument values | high | `conditional_auth` | todo |

## Notes

SIG-006 is deliberately `low`. Soroban does not guarantee sibling ordering
across host versions, so this check reports informationally and never fails a
build by default.

SIG-009 targets `try_*` client calls whose `Result` is discarded, which makes an
authorization failure look like success to the caller.
