//! Assert that a contract demands the authorization its `sigil.toml` declares.
//!
//! Usage from a contract's own test suite:
//!
//! ```ignore
//! let env = Env::default();
//! env.mock_all_auths();
//! client.transfer(&from, &to, &100);
//!
//! let bindings = Bindings::new().with("from", from.clone());
//! sigil_test::assert_auth(&env, &spec, "transfer", &bindings);
//! ```
//!
//! `mock_all_auths` lets every authorization succeed while recording what was
//! demanded, so `env.auths()` describes the contract's real authorization
//! surface. A contract that never calls `require_auth` records nothing, which
//! is what makes a missing check visible instead of silent.
//!
//! Call this immediately after the invocation under test. `env.auths()`
//! describes only the most recent call, so a read-only getter in between will
//! clear it and every check will report a missing authorization that was
//! actually demanded.

use sigil_spec::Spec;
use soroban_sdk::testutils::{AuthorizedFunction, AuthorizedInvocation};
use soroban_sdk::{Address, Env, Symbol};
use std::collections::BTreeMap;

/// Maps binding names in a spec to the addresses used in a given test run.
#[derive(Debug, Default, Clone)]
pub struct Bindings {
    map: BTreeMap<String, Address>,
}

impl Bindings {
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with(mut self, name: &str, address: Address) -> Self {
        self.map.insert(name.to_string(), address);
        self
    }

    pub fn get(&self, name: &str) -> Option<&Address> {
        self.map.get(name)
    }
}

/// A divergence between the declared surface and the observed one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Finding {
    /// SIG-001: the spec requires this binding to authorize, and nobody did.
    MissingAuthorization { function: String, binding: String },
    /// SIG-002: someone authorized, but not the address the spec names. This is
    /// the shape of demanding authorization from the caller rather than from the
    /// account whose funds move.
    WrongAuthorizer {
        function: String,
        expected_binding: String,
        actual: String,
    },
    /// SIG-003: the authorization tree contains a call the spec does not
    /// declare. Signing for the outer call also signed for this one.
    UndeclaredSubinvocation {
        function: String,
        contract: String,
        sub_function: String,
    },
    /// SIG-004: the spec declares a sub-invocation the contract never made.
    MissingSubinvocation { function: String, declared: String },
    /// SIG-005: the spec declares an authorization requirement, but a caller
    /// without it still succeeded.
    RequirementNotEnforced { function: String, declared: String },
    /// SIG-011: an address authorized that the spec does not name.
    UnexpectedAuthorization { function: String, address: String },
    /// The spec names a binding the test did not supply an address for.
    UnboundBinding { function: String, binding: String },
    /// The function is not described in the spec, so there is nothing to assert.
    FunctionNotDeclared { function: String },
}

impl std::fmt::Display for Finding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Finding::MissingAuthorization { function, binding } => write!(
                f,
                "SIG-001 {function}: spec requires '{binding}' to authorize, but nothing did"
            ),
            Finding::WrongAuthorizer {
                function,
                expected_binding,
                actual,
            } => write!(
                f,
                "SIG-002 {function}: spec requires '{expected_binding}' to authorize, but {actual} did instead"
            ),
            Finding::UndeclaredSubinvocation {
                function,
                contract,
                sub_function,
            } => write!(
                f,
                "SIG-003 {function}: authorizes an undeclared call to {contract}::{sub_function}"
            ),
            Finding::MissingSubinvocation { function, declared } => write!(
                f,
                "SIG-004 {function}: spec declares sub-invocation '{declared}', which never happened"
            ),
            Finding::RequirementNotEnforced { function, declared } => write!(
                f,
                "SIG-005 {function}: spec requires '{declared}' to authorize, but a caller without that authorization succeeded"
            ),
            Finding::UnexpectedAuthorization { function, address } => write!(
                f,
                "SIG-011 {function}: {address} authorized but the spec does not name it"
            ),
            Finding::UnboundBinding { function, binding } => write!(
                f,
                "{function}: spec names binding '{binding}' but the test supplied no address"
            ),
            Finding::FunctionNotDeclared { function } => {
                write!(f, "{function} is not declared in the spec")
            }
        }
    }
}

/// The strkey a human would paste into an explorer.
///
/// `Debug` renders `Contract(C...)`, which is noise in a finding message and
/// invites someone to copy the wrapper along with the address.
fn strkey(address: &Address) -> String {
    let s = address.to_string();
    let mut buf = std::vec![0u8; s.len() as usize];
    s.copy_into_slice(&mut buf);
    String::from_utf8(buf).unwrap_or_else(|_| strkey(address))
}

/// Recorded authorizations whose top-level call is `function`.
fn invocations_of(env: &Env, function: &str) -> Vec<(Address, AuthorizedInvocation)> {
    let wanted = Symbol::new(env, function);
    env.auths()
        .into_iter()
        .filter(|(_, invocation)| invokes(invocation, &wanted))
        .collect()
}

/// Addresses that authorized a top-level invocation of `function`.
fn authorizers_of(env: &Env, function: &str) -> Vec<Address> {
    invocations_of(env, function)
        .into_iter()
        .map(|(address, _)| address)
        .collect()
}

/// The direct children of an authorized invocation, as (contract, function).
///
/// Direct children only. A deeper call is the concern of the contract that
/// makes it, and flattening the tree would report a grandchild as though the
/// spec's subject had invoked it.
fn direct_subinvocations(invocation: &AuthorizedInvocation) -> Vec<(Address, Symbol)> {
    invocation
        .sub_invocations
        .iter()
        .filter_map(|sub| match &sub.function {
            AuthorizedFunction::Contract((address, symbol, _)) => {
                Some((address.clone(), symbol.clone()))
            }
            _ => None,
        })
        .collect()
}

fn invokes(invocation: &AuthorizedInvocation, wanted: &Symbol) -> bool {
    match &invocation.function {
        AuthorizedFunction::Contract((_, symbol, _)) => symbol == wanted,
        _ => false,
    }
}

/// Compares the declared authorization surface against what the contract demanded.
///
/// Call after exercising the function under `mock_all_auths`.
pub fn check_auth(env: &Env, spec: &Spec, function: &str, bindings: &Bindings) -> Vec<Finding> {
    let Some(declared) = spec.function(function) else {
        return vec![Finding::FunctionNotDeclared {
            function: function.to_string(),
        }];
    };

    let observed = authorizers_of(env, function);
    let mut findings = Vec::new();
    let mut expected = Vec::new();
    let mut missing = Vec::new();

    for binding in &declared.authorizers {
        match bindings.get(binding) {
            Some(address) => {
                if !observed.contains(address) {
                    missing.push(binding.clone());
                }
                expected.push(address.clone());
            }
            None => findings.push(Finding::UnboundBinding {
                function: function.to_string(),
                binding: binding.clone(),
            }),
        }
    }

    let mut unexpected: Vec<&Address> = observed.iter().filter(|a| !expected.contains(a)).collect();

    // A required binding that did not authorize, alongside an address that did,
    // is the wrong signer rather than a missing check. Reporting it as SIG-001
    // would send the reader looking for an absent require_auth that is present.
    for binding in missing {
        if unexpected.is_empty() {
            findings.push(Finding::MissingAuthorization {
                function: function.to_string(),
                binding,
            });
        } else {
            findings.push(Finding::WrongAuthorizer {
                function: function.to_string(),
                expected_binding: binding,
                actual: strkey(unexpected.remove(0)),
            });
        }
    }

    for address in unexpected {
        findings.push(Finding::UnexpectedAuthorization {
            function: function.to_string(),
            address: strkey(address),
        });
    }

    // Sub-invocations answer a different question from authorizers: not "who
    // approved this call" but "what else did approving it approve".
    let observed_subs: Vec<(Address, Symbol)> = invocations_of(env, function)
        .iter()
        .flat_map(|(_, invocation)| direct_subinvocations(invocation))
        .collect();

    let mut declared_subs = Vec::new();
    for sub in declared.parsed_subinvocations() {
        match bindings.get(sub.binding) {
            Some(address) => declared_subs.push((
                address.clone(),
                Symbol::new(env, sub.function),
                format!("{}::{}", sub.binding, sub.function),
            )),
            None => findings.push(Finding::UnboundBinding {
                function: function.to_string(),
                binding: sub.binding.to_string(),
            }),
        }
    }

    // Multiset, not set. Declaring token::transfer once authorizes exactly one
    // transfer. A second one is a second movement of the payer's money, and
    // matching by name alone would wave it through because it is the same
    // contract and the same function as the payment the payer agreed to.
    let mut unmatched = declared_subs.clone();
    for (address, symbol) in &observed_subs {
        match unmatched
            .iter()
            .position(|(a, s, _)| a == address && s == symbol)
        {
            Some(i) => {
                unmatched.remove(i);
            }
            None => findings.push(Finding::UndeclaredSubinvocation {
                function: function.to_string(),
                contract: strkey(address),
                sub_function: format!("{symbol:?}"),
            }),
        }
    }

    for (_, _, label) in unmatched {
        findings.push(Finding::MissingSubinvocation {
            function: function.to_string(),
            declared: label,
        });
    }

    findings
}

/// What happened when a function was called without the authorization its spec
/// declares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The call went through.
    Succeeded,
    /// The call was rejected.
    Rejected,
}

/// SIG-005: a declared authorization requirement must actually be enforced.
///
/// [`check_auth`] runs under `mock_all_auths`, where every authorization
/// succeeds, so it can only report what a contract *demanded*. It cannot tell
/// you whether an unauthorized caller is turned away. A function that demands
/// authorization from an address the caller supplies looks perfectly healthy
/// there: somebody authorized, and the tree is exactly as declared. The caller
/// simply passed their own address.
///
/// So the caller drives the negative case themselves, granting authorization
/// only to an identity that should not qualify, and reports what happened:
///
/// ```ignore
/// env.mock_auths(&[MockAuth { address: &intruder, invoke: &... }]);
/// let outcome = match client.try_set_fee(&intruder, &99) {
///     Ok(_) => Outcome::Succeeded,
///     Err(_) => Outcome::Rejected,
/// };
/// assert!(check_enforced(&spec, "set_fee", outcome).is_empty());
/// ```
pub fn check_enforced(spec: &Spec, function: &str, outcome: Outcome) -> Vec<Finding> {
    let Some(declared) = spec.function(function) else {
        return vec![Finding::FunctionNotDeclared {
            function: function.to_string(),
        }];
    };

    // A function declared to need nobody's approval is allowed to succeed.
    if declared.authorizers.is_empty() {
        return Vec::new();
    }

    match outcome {
        Outcome::Rejected => Vec::new(),
        Outcome::Succeeded => vec![Finding::RequirementNotEnforced {
            function: function.to_string(),
            declared: declared.authorizers.join(", "),
        }],
    }
}

/// Panics with every finding if the observed surface diverges from the spec.
pub fn assert_auth(env: &Env, spec: &Spec, function: &str, bindings: &Bindings) {
    let findings = check_auth(env, spec, function, bindings);
    if !findings.is_empty() {
        let report = findings
            .iter()
            .map(|f| format!("  {f}"))
            .collect::<Vec<_>>()
            .join("\n");
        panic!("sigil: authorization surface diverges from sigil.toml\n{report}");
    }
}
