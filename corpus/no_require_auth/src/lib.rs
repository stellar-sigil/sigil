#![no_std]

//! SIG-001 corpus pair.
//!
//! Both contracts move a balance. Only one of them asks the sender for
//! permission first. The tests assert that the check reports the vulnerable
//! half and stays silent on the fixed half, which is the bar in CONTRIBUTING.md:
//! a check that cannot fail against broken code is not a check.

use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[contracttype]
pub enum Key {
    Balance(Address),
}

fn move_balance(env: &Env, from: &Address, to: &Address, amount: i128) {
    let from_balance: i128 = env
        .storage()
        .persistent()
        .get(&Key::Balance(from.clone()))
        .unwrap_or(0);
    let to_balance: i128 = env
        .storage()
        .persistent()
        .get(&Key::Balance(to.clone()))
        .unwrap_or(0);
    env.storage()
        .persistent()
        .set(&Key::Balance(from.clone()), &(from_balance - amount));
    env.storage()
        .persistent()
        .set(&Key::Balance(to.clone()), &(to_balance + amount));
}

/// Vulnerable: anyone can move anyone else's balance.
#[contract]
pub struct Vulnerable;

#[contractimpl]
impl Vulnerable {
    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        move_balance(&env, &from, &to, amount);
    }
}

/// Fixed: the sender must authorize.
#[contract]
pub struct Fixed;

#[contractimpl]
impl Fixed {
    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        from.require_auth();
        move_balance(&env, &from, &to, amount);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use sigil_spec::Spec;
    use sigil_test::{check_auth, Bindings, Finding};
    use soroban_sdk::testutils::Address as _;

    const SPEC: &str = include_str!("../sigil.toml");

    struct Run {
        env: Env,
        bindings: Bindings,
    }

    fn exercise_vulnerable() -> Run {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register(Vulnerable, ());
        let client = VulnerableClient::new(&env, &id);
        let from = Address::generate(&env);
        let to = Address::generate(&env);
        client.transfer(&from, &to, &100);
        Run {
            bindings: Bindings::new().with("from", from),
            env,
        }
    }

    fn exercise_fixed() -> Run {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register(Fixed, ());
        let client = FixedClient::new(&env, &id);
        let from = Address::generate(&env);
        let to = Address::generate(&env);
        client.transfer(&from, &to, &100);
        Run {
            bindings: Bindings::new().with("from", from),
            env,
        }
    }

    #[test]
    fn sig_001_reports_the_vulnerable_contract() {
        let spec = Spec::parse(SPEC).expect("spec parses");
        let run = exercise_vulnerable();
        let findings = check_auth(&run.env, &spec, "transfer", &run.bindings);
        assert_eq!(
            findings,
            std::vec![Finding::MissingAuthorization {
                function: "transfer".into(),
                binding: "from".into(),
            }]
        );
    }

    #[test]
    fn sig_001_is_silent_on_the_fixed_contract() {
        let spec = Spec::parse(SPEC).expect("spec parses");
        let run = exercise_fixed();
        let findings = check_auth(&run.env, &spec, "transfer", &run.bindings);
        assert!(findings.is_empty(), "unexpected findings: {findings:?}");
    }

    /// The transfer really does move value in both contracts, so the pair
    /// differs only in the authorization check and not in what it does.
    #[test]
    fn both_contracts_move_the_balance() {
        let env = Env::default();
        env.mock_all_auths();
        let from = Address::generate(&env);
        let to = Address::generate(&env);

        let vulnerable = VulnerableClient::new(&env, &env.register(Vulnerable, ()));
        let fixed = FixedClient::new(&env, &env.register(Fixed, ()));
        vulnerable.transfer(&from, &to, &100);
        fixed.transfer(&from, &to, &100);
    }
}
