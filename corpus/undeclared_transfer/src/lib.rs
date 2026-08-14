#![no_std]

//! SIG-003 corpus pair.
//!
//! A signature covers the whole authorization tree beneath it, not just the
//! call the signer believes they are approving. Both gateways here pay the
//! merchant correctly. One of them also moves the payer's money somewhere else
//! under the same signature.

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

/// A minimal token. `transfer` demands authorization from the sender, so it
/// shows up as a sub-invocation in the caller's authorization tree.
#[contract]
pub struct Token;

#[contractimpl]
impl Token {
    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        from.require_auth();
        let f = balance(&env, &from);
        let t = balance(&env, &to);
        env.storage()
            .persistent()
            .set(&Key::Balance(from), &(f - amount));
        env.storage()
            .persistent()
            .set(&Key::Balance(to), &(t + amount));
    }

    pub fn balance_of(env: Env, who: Address) -> i128 {
        balance(&env, &who)
    }

    pub fn mint(env: Env, to: Address, amount: i128) {
        let t = balance(&env, &to);
        env.storage()
            .persistent()
            .set(&Key::Balance(to), &(t + amount));
    }
}

/// Fixed: pays the merchant and nothing else.
#[contract]
pub struct Fixed;

#[contractimpl]
impl Fixed {
    pub fn pay(env: Env, payer: Address, merchant: Address, amount: i128, token: Address) {
        payer.require_auth();
        TokenClient::new(&env, &token).transfer(&payer, &merchant, &amount);
    }
}

/// Vulnerable: pays the merchant, then moves a cut to an address the payer
/// never agreed to, under the same signature.
#[contract]
pub struct Vulnerable;

#[contractimpl]
impl Vulnerable {
    pub fn pay(
        env: Env,
        payer: Address,
        merchant: Address,
        amount: i128,
        token: Address,
        skimmer: Address,
    ) {
        payer.require_auth();
        let client = TokenClient::new(&env, &token);
        client.transfer(&payer, &merchant, &amount);
        client.transfer(&payer, &skimmer, &(amount / 10));
    }
}

/// Declared but absent: takes the payer's authorization for a payment it never
/// makes. The spec says signing `pay` authorizes one `token::transfer`, and
/// this contract makes none, so the signature bought the payer nothing.
#[contract]
pub struct NeverPays;

#[contractimpl]
impl NeverPays {
    pub fn pay(env: Env, payer: Address, merchant: Address, amount: i128, token: Address) {
        let _ = (merchant, amount, token, &env);
        payer.require_auth();
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

    struct Setup {
        env: Env,
        token: Address,
        payer: Address,
        merchant: Address,
        skimmer: Address,
    }

    fn setup() -> Setup {
        let env = Env::default();
        env.mock_all_auths();
        let token = env.register(Token, ());
        let payer = Address::generate(&env);
        let merchant = Address::generate(&env);
        let skimmer = Address::generate(&env);
        TokenClient::new(&env, &token).mint(&payer, &10_000);
        Setup {
            env,
            token,
            payer,
            merchant,
            skimmer,
        }
    }

    fn bindings(s: &Setup) -> Bindings {
        Bindings::new()
            .with("payer", s.payer.clone())
            .with("token", s.token.clone())
    }

    #[test]
    fn sig_003_reports_the_skimming_gateway() {
        let s = setup();
        let gateway = s.env.register(Vulnerable, ());
        VulnerableClient::new(&s.env, &gateway).pay(
            &s.payer,
            &s.merchant,
            &1_000,
            &s.token,
            &s.skimmer,
        );

        let spec = Spec::parse(SPEC).expect("spec parses");
        let findings = check_auth(&s.env, &spec, "pay", &bindings(&s));

        assert!(
            findings.iter().any(|f| matches!(
                f,
                Finding::UndeclaredSubinvocation { function, .. } if function == "pay"
            )),
            "expected SIG-003, got {findings:?}"
        );
    }

    #[test]
    fn sig_003_is_silent_on_the_honest_gateway() {
        let s = setup();
        let gateway = s.env.register(Fixed, ());
        FixedClient::new(&s.env, &gateway).pay(&s.payer, &s.merchant, &1_000, &s.token);

        let spec = Spec::parse(SPEC).expect("spec parses");
        let findings = check_auth(&s.env, &spec, "pay", &bindings(&s));

        assert!(findings.is_empty(), "unexpected findings: {findings:?}");
    }

    /// The skim is invisible to an authorizer-only check: the payer really did
    /// authorize, and no unexpected address appears anywhere.
    #[test]
    fn the_skim_is_invisible_to_a_top_level_check() {
        let s = setup();
        let gateway = s.env.register(Vulnerable, ());
        VulnerableClient::new(&s.env, &gateway).pay(
            &s.payer,
            &s.merchant,
            &1_000,
            &s.token,
            &s.skimmer,
        );

        let spec = Spec::parse(SPEC).expect("spec parses");
        let findings = check_auth(&s.env, &spec, "pay", &bindings(&s));

        assert!(
            !findings.iter().any(|f| matches!(
                f,
                Finding::MissingAuthorization { .. }
                    | Finding::WrongAuthorizer { .. }
                    | Finding::UnexpectedAuthorization { .. }
            )),
            "the authorizer set should be clean here: {findings:?}"
        );
    }

    #[test]
    fn sig_004_reports_the_gateway_that_never_pays() {
        let s = setup();
        let gateway = s.env.register(NeverPays, ());
        NeverPaysClient::new(&s.env, &gateway).pay(&s.payer, &s.merchant, &1_000, &s.token);

        let spec = Spec::parse(SPEC).expect("spec parses");
        let findings = check_auth(&s.env, &spec, "pay", &bindings(&s));

        assert_eq!(
            findings,
            std::vec![Finding::MissingSubinvocation {
                function: "pay".into(),
                declared: "token::transfer".into(),
            }]
        );
    }

    #[test]
    fn sig_004_is_silent_on_the_honest_gateway() {
        let s = setup();
        let gateway = s.env.register(Fixed, ());
        FixedClient::new(&s.env, &gateway).pay(&s.payer, &s.merchant, &1_000, &s.token);

        let spec = Spec::parse(SPEC).expect("spec parses");
        let findings = check_auth(&s.env, &spec, "pay", &bindings(&s));

        assert!(
            !findings
                .iter()
                .any(|f| matches!(f, Finding::MissingSubinvocation { .. })),
            "unexpected SIG-004: {findings:?}"
        );
    }

    /// The merchant is really paid by the honest gateway, and really not paid by
    /// the one that only takes the signature.
    #[test]
    fn the_declared_payment_actually_happens() {
        let s = setup();
        let token = TokenClient::new(&s.env, &s.token);

        let honest = s.env.register(Fixed, ());
        FixedClient::new(&s.env, &honest).pay(&s.payer, &s.merchant, &1_000, &s.token);
        assert_eq!(token.balance_of(&s.merchant), 1_000);

        let absent = s.env.register(NeverPays, ());
        NeverPaysClient::new(&s.env, &absent).pay(&s.payer, &s.merchant, &1_000, &s.token);
        assert_eq!(token.balance_of(&s.merchant), 1_000, "nothing more moved");
    }

    /// The money really moves, so the pair differs in behaviour and not only in
    /// what the authorization tree records.
    #[test]
    fn the_skimmer_is_actually_paid() {
        let s = setup();
        let gateway = s.env.register(Vulnerable, ());
        VulnerableClient::new(&s.env, &gateway).pay(
            &s.payer,
            &s.merchant,
            &1_000,
            &s.token,
            &s.skimmer,
        );
        assert_eq!(
            TokenClient::new(&s.env, &s.token).balance_of(&s.skimmer),
            100
        );
    }
}
