//! Parser for `sigil.toml`. See `docs/SPEC.md`.
//!
//! The spec names bindings rather than addresses, because addresses are
//! generated fresh on every test run. Binding names are resolved to addresses
//! by the caller at assertion time.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Spec {
    pub contract: Contract,
    #[serde(default, rename = "function")]
    pub functions: Vec<Function>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Contract {
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Function {
    pub name: String,
    /// Binding names whose addresses must all appear as authorizers. An empty
    /// list asserts the function demands no authorization at all, which is a
    /// different claim from leaving the function out of the spec.
    #[serde(default)]
    pub authorizers: Vec<String>,
    /// Expected sub-invocations, written `binding::fn_name`.
    #[serde(default)]
    pub subinvocations: Vec<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Parse(String),
    EmptyContractName,
    EmptyFunctionName,
    DuplicateFunction(String),
    BlankAuthorizer(String),
    MalformedSubinvocation { function: String, value: String },
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Parse(e) => write!(f, "could not parse sigil.toml: {e}"),
            Error::EmptyContractName => write!(f, "contract.name is empty"),
            Error::EmptyFunctionName => write!(f, "a function has an empty name"),
            Error::DuplicateFunction(n) => write!(f, "function '{n}' is declared more than once"),
            Error::BlankAuthorizer(n) => {
                write!(f, "function '{n}' lists a blank authorizer binding")
            }
            Error::MalformedSubinvocation { function, value } => write!(
                f,
                "function '{function}' has subinvocation '{value}', expected 'binding::fn_name'"
            ),
        }
    }
}

impl std::error::Error for Error {}

impl Spec {
    pub fn parse(input: &str) -> Result<Self, Error> {
        let spec: Spec = toml::from_str(input).map_err(|e| Error::Parse(e.to_string()))?;
        spec.validate()?;
        Ok(spec)
    }

    pub fn to_toml(&self) -> Result<String, Error> {
        toml::to_string_pretty(self).map_err(|e| Error::Parse(e.to_string()))
    }

    pub fn function(&self, name: &str) -> Option<&Function> {
        self.functions.iter().find(|f| f.name == name)
    }

    fn validate(&self) -> Result<(), Error> {
        if self.contract.name.trim().is_empty() {
            return Err(Error::EmptyContractName);
        }

        let mut seen = BTreeSet::new();
        for f in &self.functions {
            if f.name.trim().is_empty() {
                return Err(Error::EmptyFunctionName);
            }
            if !seen.insert(f.name.as_str()) {
                return Err(Error::DuplicateFunction(f.name.clone()));
            }
            if f.authorizers.iter().any(|a| a.trim().is_empty()) {
                return Err(Error::BlankAuthorizer(f.name.clone()));
            }
            for sub in &f.subinvocations {
                let mut parts = sub.split("::");
                let binding = parts.next().unwrap_or_default();
                let func = parts.next().unwrap_or_default();
                if binding.trim().is_empty() || func.trim().is_empty() || parts.next().is_some() {
                    return Err(Error::MalformedSubinvocation {
                        function: f.name.clone(),
                        value: sub.clone(),
                    });
                }
            }
        }
        Ok(())
    }
}

/// A parsed `binding::fn_name` sub-invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subinvocation<'a> {
    pub binding: &'a str,
    pub function: &'a str,
}

impl Function {
    /// Parsed sub-invocations. Safe to unwrap internally because [`Spec::parse`]
    /// rejects malformed entries.
    pub fn parsed_subinvocations(&self) -> Vec<Subinvocation<'_>> {
        self.subinvocations
            .iter()
            .filter_map(|s| {
                let (binding, function) = s.split_once("::")?;
                Some(Subinvocation { binding, function })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
[contract]
name = "token"

[[function]]
name = "transfer"
authorizers = ["from"]
subinvocations = []

[[function]]
name = "burn_from"
authorizers = ["spender"]
subinvocations = ["token::burn"]

[[function]]
name = "balance"
authorizers = []
"#;

    #[test]
    fn parses_the_documented_sample() {
        let spec = Spec::parse(SAMPLE).expect("parses");
        assert_eq!(spec.contract.name, "token");
        assert_eq!(spec.functions.len(), 3);
        assert_eq!(spec.function("transfer").unwrap().authorizers, ["from"]);
    }

    #[test]
    fn empty_authorizers_is_preserved_not_dropped() {
        let spec = Spec::parse(SAMPLE).expect("parses");
        let balance = spec.function("balance").expect("balance present");
        assert!(balance.authorizers.is_empty());
        // The distinction the whole check depends on: declared-and-empty is not
        // the same as absent.
        assert!(spec.function("nonexistent").is_none());
    }

    #[test]
    fn round_trips_through_toml() {
        let spec = Spec::parse(SAMPLE).expect("parses");
        let reparsed = Spec::parse(&spec.to_toml().expect("serializes")).expect("reparses");
        assert_eq!(spec, reparsed);
    }

    #[test]
    fn subinvocations_are_split() {
        let spec = Spec::parse(SAMPLE).expect("parses");
        let subs = spec.function("burn_from").unwrap().parsed_subinvocations();
        assert_eq!(subs.len(), 1);
        assert_eq!(subs[0].binding, "token");
        assert_eq!(subs[0].function, "burn");
    }

    #[test]
    fn rejects_duplicate_functions() {
        let input = r#"
[contract]
name = "t"
[[function]]
name = "transfer"
[[function]]
name = "transfer"
"#;
        assert_eq!(
            Spec::parse(input),
            Err(Error::DuplicateFunction("transfer".into()))
        );
    }

    #[test]
    fn rejects_malformed_subinvocation() {
        let input = r#"
[contract]
name = "t"
[[function]]
name = "transfer"
subinvocations = ["token:burn"]
"#;
        assert_eq!(
            Spec::parse(input),
            Err(Error::MalformedSubinvocation {
                function: "transfer".into(),
                value: "token:burn".into()
            })
        );
    }

    #[test]
    fn rejects_empty_contract_name() {
        let input = r#"
[contract]
name = "  "
"#;
        assert_eq!(Spec::parse(input), Err(Error::EmptyContractName));
    }

    #[test]
    fn rejects_blank_authorizer() {
        let input = r#"
[contract]
name = "t"
[[function]]
name = "transfer"
authorizers = ["from", ""]
"#;
        assert_eq!(
            Spec::parse(input),
            Err(Error::BlankAuthorizer("transfer".into()))
        );
    }
}
