#![no_std]

//! SIG-002 corpus pair.
//!
//! Both vaults debit `owner` and credit `caller`. Both call `require_auth`, so
//! neither looks unguarded on a skim. They differ in who is asked, and only one
//! of them asks the account that loses the money.

use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[contracttype]
pub enum Key {
    Balance(Address),
}

fn balance(env: &Env, who: &Address) -> i128 {
    env.storage()
        .persistent()
        .get(&Key::Balance(who.clone()))
        .unwrap_or(0)
}

fn debit_owner_credit_caller(env: &Env, caller: &Address, owner: &Address, amount: i128) {
    let owner_balance = balance(env, owner);
    let caller_balance = balance(env, caller);
    env.storage()
        .persistent()
        .set(&Key::Balance(owner.clone()), &(owner_balance - amount));
    env.storage()
        .persistent()
        .set(&Key::Balance(caller.clone()), &(caller_balance + amount));
}

/// Vulnerable: asks the caller, then spends the owner's balance. Any address
/// can drain any other by passing itself as `caller`.
#[contract]
pub struct Vulnerable;

#[contractimpl]
impl Vulnerable {
    pub fn withdraw(env: Env, caller: Address, owner: Address, amount: i128) {
        caller.require_auth();
        debit_owner_credit_caller(&env, &caller, &owner, amount);
    }
}

/// Fixed: asks the account whose balance is debited.
#[contract]
pub struct Fixed;

#[contractimpl]
impl Fixed {
    pub fn withdraw(env: Env, caller: Address, owner: Address, amount: i128) {
        owner.require_auth();
        debit_owner_credit_caller(&env, &caller, &owner, amount);
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

    #[test]
    fn sig_002_reports_the_vulnerable_vault() {
        let env = Env::default();
        env.mock_all_auths();
        let client = VulnerableClient::new(&env, &env.register(Vulnerable, ()));
        let attacker = Address::generate(&env);
        let victim = Address::generate(&env);
        client.withdraw(&attacker, &victim, &100);

        let spec = Spec::parse(SPEC).expect("spec parses");
        let bindings = Bindings::new().with("owner", victim);
        let findings = check_auth(&env, &spec, "withdraw", &bindings);

        assert_eq!(findings.len(), 1, "got {findings:?}");
        assert!(
            matches!(
                &findings[0],
                Finding::WrongAuthorizer { function, expected_binding, .. }
                    if function == "withdraw" && expected_binding == "owner"
            ),
            "expected SIG-002, got {:?}",
            findings[0]
        );
    }

    #[test]
    fn sig_002_is_silent_on_the_fixed_vault() {
        let env = Env::default();
        env.mock_all_auths();
        let client = FixedClient::new(&env, &env.register(Fixed, ()));
        let caller = Address::generate(&env);
        let owner = Address::generate(&env);
        client.withdraw(&caller, &owner, &100);

        let spec = Spec::parse(SPEC).expect("spec parses");
        let bindings = Bindings::new().with("owner", owner);
        let findings = check_auth(&env, &spec, "withdraw", &bindings);

        assert!(findings.is_empty(), "unexpected findings: {findings:?}");
    }

    /// SIG-002 is not SIG-001. The vulnerable vault does call require_auth, so a
    /// check that only looked for a missing call would report nothing here.
    #[test]
    fn the_vulnerable_vault_does_demand_some_authorization() {
        let env = Env::default();
        env.mock_all_auths();
        let client = VulnerableClient::new(&env, &env.register(Vulnerable, ()));
        let attacker = Address::generate(&env);
        client.withdraw(&attacker, &Address::generate(&env), &100);
        assert!(!env.auths().is_empty());
    }
}
