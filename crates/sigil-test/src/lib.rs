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
    /// SIG-001 / SIG-002: the spec requires this binding to authorize, and it did not.
    MissingAuthorization { function: String, binding: String },
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
                "SIG-001 {function}: spec requires '{binding}' to authorize, but it did not"
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

/// Addresses that authorized a top-level invocation of `function`.
fn authorizers_of(env: &Env, function: &str) -> Vec<Address> {
    let wanted = Symbol::new(env, function);
    env.auths()
        .into_iter()
        .filter(|(_, invocation)| invokes(invocation, &wanted))
        .map(|(address, _)| address)
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

    for binding in &declared.authorizers {
        match bindings.get(binding) {
            Some(address) => {
                if !observed.contains(address) {
                    findings.push(Finding::MissingAuthorization {
                        function: function.to_string(),
                        binding: binding.clone(),
                    });
                }
                expected.push(address.clone());
            }
            None => findings.push(Finding::UnboundBinding {
                function: function.to_string(),
                binding: binding.clone(),
            }),
        }
    }

    for address in &observed {
        if !expected.contains(address) {
            findings.push(Finding::UnexpectedAuthorization {
                function: function.to_string(),
                address: format!("{address:?}"),
            });
        }
    }

    findings
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
