#![no_std]

//! SIG-005 corpus pair.
//!
//! Both contracts call `require_auth` on the way to setting the fee, so under
//! `mock_all_auths` both record an authorization and both look correct. The
//! difference is *whose* approval is demanded: one asks the address the caller
//! handed in, the other asks the admin it stored at initialization.
//!
//! This is the case that a surface check cannot see. Somebody authorized, the
//! tree matches the spec, and the caller simply passed their own address.

use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[contracttype]
pub enum Key {
    Admin,
    Fee,
}

fn admin(env: &Env) -> Address {
    env.storage()
        .instance()
        .get(&Key::Admin)
        .expect("initialized")
}

/// Vulnerable: requires authorization from an address the caller supplies.
/// Anyone can satisfy it by naming themselves.
#[contract]
pub struct Vulnerable;

#[contractimpl]
impl Vulnerable {
    pub fn init(env: Env, admin: Address) {
        env.storage().instance().set(&Key::Admin, &admin);
    }

    pub fn set_fee(env: Env, caller: Address, fee: i128) {
        caller.require_auth();
        env.storage().instance().set(&Key::Fee, &fee);
    }

    pub fn fee(env: Env) -> i128 {
        env.storage().instance().get(&Key::Fee).unwrap_or(0)
    }
}

/// Fixed: requires authorization from the stored admin, whatever the caller
/// claims to be.
#[contract]
pub struct Fixed;

#[contractimpl]
impl Fixed {
    pub fn init(env: Env, admin: Address) {
        env.storage().instance().set(&Key::Admin, &admin);
    }

    pub fn set_fee(env: Env, caller: Address, fee: i128) {
        let _ = caller;
        admin(&env).require_auth();
        env.storage().instance().set(&Key::Fee, &fee);
    }

    pub fn fee(env: Env) -> i128 {
        env.storage().instance().get(&Key::Fee).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use sigil_spec::Spec;
    use sigil_test::{check_auth, check_enforced, Bindings, Finding, Outcome};
    use soroban_sdk::testutils::{Address as _, MockAuth, MockAuthInvoke};
    use soroban_sdk::IntoVal;

    const SPEC: &str = include_str!("../sigil.toml");

    #[test]
    fn sig_005_reports_the_open_gate() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register(Vulnerable, ());
        let client = VulnerableClient::new(&env, &id);
        let admin = Address::generate(&env);
        let intruder = Address::generate(&env);
        client.init(&admin);

        // The intruder may authorize for itself and for nobody else.
        env.mock_auths(&[MockAuth {
            address: &intruder,
            invoke: &MockAuthInvoke {
                contract: &id,
                fn_name: "set_fee",
                args: (intruder.clone(), 99i128).into_val(&env),
                sub_invokes: &[],
            },
        }]);
        let outcome = match client.try_set_fee(&intruder, &99) {
            Ok(_) => Outcome::Succeeded,
            Err(_) => Outcome::Rejected,
        };

        let spec = Spec::parse(SPEC).expect("spec parses");
        let findings = check_enforced(&spec, "set_fee", outcome);

        assert_eq!(
            findings,
            std::vec![Finding::RequirementNotEnforced {
                function: "set_fee".into(),
                declared: "admin".into(),
            }],
            "the intruder set the fee without being admin"
        );
        assert_eq!(client.fee(), 99);
    }

    #[test]
    fn sig_005_is_silent_on_the_real_gate() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register(Fixed, ());
        let client = FixedClient::new(&env, &id);
        let admin = Address::generate(&env);
        let intruder = Address::generate(&env);
        client.init(&admin);

        env.mock_auths(&[MockAuth {
            address: &intruder,
            invoke: &MockAuthInvoke {
                contract: &id,
                fn_name: "set_fee",
                args: (intruder.clone(), 99i128).into_val(&env),
                sub_invokes: &[],
            },
        }]);
        let outcome = match client.try_set_fee(&intruder, &99) {
            Ok(_) => Outcome::Succeeded,
            Err(_) => Outcome::Rejected,
        };

        let spec = Spec::parse(SPEC).expect("spec parses");
        assert!(
            check_enforced(&spec, "set_fee", outcome).is_empty(),
            "the admin gate should have refused"
        );
        assert_eq!(client.fee(), 0, "the fee must not have changed");

        // Positive control. Without it this test passes against a contract that
        // rejects everyone, including one whose body is a bare panic: the
        // intruder is refused and the fee stays 0 for the wrong reason.
        // `Err(_)` cannot tell an authorization rejection from any other trap,
        // so the proof that the gate is a gate is that the admin gets through.
        env.mock_auths(&[MockAuth {
            address: &admin,
            invoke: &MockAuthInvoke {
                contract: &id,
                fn_name: "set_fee",
                args: (admin.clone(), 40i128).into_val(&env),
                sub_invokes: &[],
            },
        }]);
        client.set_fee(&admin, &40);
        assert_eq!(client.fee(), 40, "the admin must be able to set the fee");
    }

    /// Why SIG-005 is not redundant with the surface checks: under
    /// `mock_all_auths` the vulnerable contract looks correct. It demands
    /// authorization, the admin supplies it, and check_auth is completely
    /// silent. Only calling as somebody else exposes the gate.
    #[test]
    fn the_open_gate_looks_healthy_to_a_surface_check() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register(Vulnerable, ());
        let client = VulnerableClient::new(&env, &id);
        let admin = Address::generate(&env);
        client.init(&admin);

        client.set_fee(&admin, &7);

        let spec = Spec::parse(SPEC).expect("spec parses");
        let bindings = Bindings::new().with("admin", admin);
        let findings = check_auth(&env, &spec, "set_fee", &bindings);

        assert!(
            findings.is_empty(),
            "surface check should see nothing wrong here: {findings:?}"
        );
    }
}
