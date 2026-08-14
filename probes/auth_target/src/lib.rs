#![no_std]

//! The contract Sigil's live-network probes are run against.
//!
//! Deliberately small. A probe asserts something about how the network handles
//! an authorization entry, so the contract itself needs to do nothing except
//! demand authorization from one named address and record that it ran.

use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[contracttype]
pub enum Key {
    Value(Address),
}

#[contract]
pub struct AuthTarget;

#[contractimpl]
impl AuthTarget {
    /// Requires `owner` to authorize. Every probe either satisfies this
    /// correctly (the control) or tries to satisfy it improperly (the attempt).
    pub fn set_value(env: Env, owner: Address, value: i128) {
        owner.require_auth();
        env.storage().persistent().set(&Key::Value(owner), &value);
    }

    pub fn get_value(env: Env, owner: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&Key::Value(owner))
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::Address as _;

    #[test]
    fn set_value_requires_the_owner() {
        let env = Env::default();
        env.mock_all_auths();
        let client = AuthTargetClient::new(&env, &env.register(AuthTarget, ()));
        let owner = Address::generate(&env);

        client.set_value(&owner, &42);
        // Read auths before any further invocation: env.auths() describes the
        // most recent call, and get_value would clear it.
        //
        // Assert who authorized, not how many did. Counting alone still passes
        // when the contract demands authorization from itself instead of the
        // owner, and every probe in docs/PROBES.md is defined against this
        // contract as "control = the owner authorizes".
        let auths = env.auths();
        assert_eq!(auths.len(), 1);
        assert_eq!(auths[0].0, owner, "set_value must demand the owner");

        assert_eq!(client.get_value(&owner), 42);
    }
}
