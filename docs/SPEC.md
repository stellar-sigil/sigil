# sigil.toml

The declared authorization surface of a contract. Checks compare what the
contract actually demands against what this file says it should.

## Shape

```toml
[contract]
name = "token"

[[function]]
name = "transfer"
authorizers = ["from"]
subinvocations = []

[[function]]
name = "set_admin"
authorizers = ["admin"]

[[function]]
name = "balance"
authorizers = []
```

## Directives

| directive | applies to | meaning | status |
|-----------|-----------|---------|--------|
| `contract.name` | contract | label used in reports | done |
| `function.name` | function | the contract function being described | done |
| `function.authorizers` | function | binding names whose addresses must all appear as authorizers. An empty list asserts the function demands no authorization. | done |
| `function.subinvocations` | function | sub-invocations the auth tree is expected to contain, as `binding::fn_name` | done |
| `function.expiration_max_ledgers` | function | reject entries whose validity window exceeds this | todo |
| `function.custom_account` | function | the authorizer is a `__check_auth` contract, not a keypair | todo |
| `function.any_of` | function | any one of these binding sets satisfies the rule | todo |
| `function.forbid_authorizers` | function | addresses that must never satisfy the rule | todo |

`authorizers` names **bindings**, not addresses. Addresses are supplied by the
test at assertion time, because the same spec has to work against freshly
generated addresses on every run.

## Why an empty list is meaningful

`authorizers = []` is not the same as omitting the function. Omitting it says
nothing. An empty list is the assertion that the function demands no
authorization at all, which is what catches a view function that was made to
require auth by accident, and what makes the absence of a required check
visible rather than silent.
