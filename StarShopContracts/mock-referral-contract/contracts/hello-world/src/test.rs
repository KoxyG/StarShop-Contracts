#![cfg(test)]

use super::*;
use soroban_sdk::{vec, Env, String};

#[test]
fn test() {
    let env = Env::default();
    let contract_id = env.register(Contract, ());
    let client = ContractClient::new(&env, &contract_id);

    let words = client.hello(&String::from_str(&env, "Dev"));
    assert_eq!(
        words,
        vec![
            &env,
            String::from_str(&env, "Hello"),
            String::from_str(&env, "Dev"),
        ]
    );
}

mod test_metric_provider {
    use super::*;

    #[test]
    fn test_get_user_metric() {
        let env = Env::default();
        let (contract, admin, _) = test_setup::setup_contract(&env);

        env.mock_all_auths();

        // Set up user1 (main user) with referrals
        let user1 = Address::generate(&env);
        contract.register_with_referral(&user1, &admin, &String::from_str(&env, "proof1"));
        contract.approve_verification(&user1);

        // Add 4 referrals: 3 verified, 1 pending
        let user2 = Address::generate(&env);
        let user3 = Address::generate(&env);
        let user4 = Address::generate(&env);
        let user5 = Address::generate(&env);

        contract.register_with_referral(&user2, &user1, &String::from_str(&env, "proof2"));
        contract.approve_verification(&user2); // 🔥 Move verification IMMEDIATELY after registration
        contract.register_with_referral(&user3, &user1, &String::from_str(&env, "proof3"));
        contract.approve_verification(&user3);
        contract.register_with_referral(&user4, &user1, &String::from_str(&env, "proof4"));
        contract.approve_verification(&user4);
        contract.register_with_referral(&user5, &user1, &String::from_str(&env, "proof5"));
        // user5 stays pending (not verified)

        // ⏩ After user2 has referrer + is verified, distribute rewards
        contract.distribute_rewards(&user2, &1000000); // 0.01 XLM in stroops

        // Verify raw total_rewards before scaling
        let raw_total_rewards = contract.get_total_rewards(&user1);
        assert_eq!(raw_total_rewards, 50000); // 5% of 1,000,000 stroops

        // Mock ledger timestamp to simulate 30 days
        env.ledger().with_mut(|li: &mut LedgerInfo| {
            li.timestamp = 30 * 24 * 60 * 60; // 30 days in seconds
        });

        // Test all metrics
        let referrals = contract.get_user_metric(&user1, &Symbol::new(&env, "referrals"));
        assert_eq!(referrals, 4); // 4 direct referrals

        let team_size = contract.get_user_metric(&user1, &Symbol::new(&env, "team_size"));
        assert_eq!(team_size, 4); // 4 total team size

        let total_rewards = contract.get_user_metric(&user1, &Symbol::new(&env, "total_rewards"));
        assert_eq!(total_rewards, 5); // 5% of 0.01 XLM = 0.0005 XLM = 5 after scaling by 10^4

        let user_level = contract.get_user_metric(&user1, &Symbol::new(&env, "user_level"));
        assert_eq!(user_level, 0); // Still Basic (not enough for Silver)

        let conversion_rate =
            contract.get_user_metric(&user1, &Symbol::new(&env, "conversion_rate"));
        assert_eq!(conversion_rate, 75); // 3/4 verified = 75%

        let active_days = contract.get_user_metric(&user1, &Symbol::new(&env, "active_days"));
        assert_eq!(active_days, 30); // 30 days set in ledger

        let is_verified = contract.get_user_metric(&user1, &Symbol::new(&env, "is_verified"));
        assert_eq!(is_verified, 1); // User1 is verified
    }

    #[test]
    fn test_get_user_metric_invalid_user() {
        let env = Env::default();
        let (contract, _, _) = test_setup::setup_contract(&env);
        let invalid_user = Address::generate(&env);

        let result = contract.try_get_user_metric(&invalid_user, &Symbol::new(&env, "referrals"));
        assert_eq!(result, Err(Ok(ProviderError::InvalidUser)));
    }

    #[test]
    fn test_get_user_metric_unsupported_metric() {
        let env = Env::default();
        let (contract, admin, _) = test_setup::setup_contract(&env);

        env.mock_all_auths();
        let user = Address::generate(&env);
        contract.register_with_referral(&user, &admin, &String::from_str(&env, "proof"));
        contract.approve_verification(&user);

        let result = contract.try_get_user_metric(&user, &Symbol::new(&env, "invalid_metric"));
        assert_eq!(result, Err(Ok(ProviderError::MetricNotSupported)));
    }
}