use super::*;
use crate::types::{MilestoneRequirement, UserLevel};
use soroban_sdk::{
    testutils::{Address as _, Ledger, LedgerInfo},
    Address, Env, Symbol,
};

#[cfg(test)]
mod test_setup {
    use super::*;

    pub fn setup_contract(e: &Env) -> (ReferralContractClient, Address, Address) {
        let admin = Address::generate(e);
        let token = e.register_stellar_asset_contract_v2(admin.clone());
        let contract_id = e.register(ReferralContract, {});
        let client = ReferralContractClient::new(e, &contract_id);

        e.mock_all_auths();

        // Initialize first
        let _ = client.initialize(&admin, &token.address());

        // Set default reward rates after initialization
        let rates = RewardRates {
            level1: 500, // 5%
            level2: 200, // 2%
            level3: 100, // 1%
            max_reward_per_referral: 1000000,
        };

        client.set_reward_rates(&rates);

        (client, admin, token.address())
    }
}

mod test_admin {
    use super::*;

    #[test]
    #[should_panic(expected = "Error(Contract, #2)")]
    fn test_initialization() {
        let env = Env::default();
        let (contract, admin, token_address) = test_setup::setup_contract(&env);

        // Verify contract is initialized correctly
        assert!(!contract.get_paused_state());

        env.mock_all_auths();
        // Try to initialize again (should fail)
        let _ = contract.initialize(&admin, &token_address);
    }

    #[test]
    fn test_pause_resume() {
        let env = Env::default();
        let (contract, _, _) = test_setup::setup_contract(&env);

        env.mock_all_auths();
        // Test pause
        contract.pause_contract();
        assert!(contract.get_paused_state());

        // Test resume
        contract.resume_contract();
        assert!(!contract.get_paused_state());
    }
}

mod test_verification {
    use super::*;

    #[test]
    fn test_verification_flow() {
        let env = Env::default();
        let (contract, admin, _) = test_setup::setup_contract(&env);
        let user = Address::generate(&env);

        env.mock_all_auths();

        // Register user with admin as referrer first
        contract.register_with_referral(&user, &admin, &String::from_str(&env, "proof123"));

        // Check pending status
        let status = contract.get_verification_status(&user);
        assert!(matches!(status, VerificationStatus::Pending));

        // Approve verification
        contract.approve_verification(&user);
        let status = contract.get_verification_status(&user);
        assert!(matches!(status, VerificationStatus::Verified));
    }
}

mod test_referral {
    use super::*;

    #[test]
    fn test_referral_registration() {
        let env = Env::default();
        let (contract, admin, _) = test_setup::setup_contract(&env);

        env.mock_all_auths();
        // First user referred by admin
        let user1 = Address::generate(&env);
        contract.register_with_referral(&user1, &admin, &String::from_str(&env, "proof1"));
        contract.approve_verification(&user1);

        env.mock_all_auths();
        // Second user referred by first user
        let user2 = Address::generate(&env);
        contract.register_with_referral(&user2, &user1, &String::from_str(&env, "proof2"));

        // Verify referral relationship
        let user_info = contract.get_user_info(&user2);
        assert_eq!(user_info.referrer, Some(user1));
    }

    #[test]
    fn test_team_size_update() {
        let env = Env::default();
        let (contract, admin, _) = test_setup::setup_contract(&env);

        env.mock_all_auths();
        // First user referred by admin
        let user1 = Address::generate(&env);
        contract.register_with_referral(&user1, &admin, &String::from_str(&env, "proof1"));
        contract.approve_verification(&user1);

        // Register multiple referrals under first user
        for _ in 0..3 {
            env.mock_all_auths();
            let user = Address::generate(&env);
            contract.register_with_referral(&user, &user1, &String::from_str(&env, "proof123"));
        }

        // Check team size
        let team_size = contract.get_team_size(&user1);
        assert_eq!(team_size, 3);
    }
}

mod test_rewards {
    use super::*;

    #[test]
    fn test_reward_distribution() {
        let env = Env::default();
        let (contract, admin, _) = test_setup::setup_contract(&env);

        env.mock_all_auths();
        // First user referred by admin
        let user1 = Address::generate(&env);
        contract.register_with_referral(&user1, &admin, &String::from_str(&env, "proof1"));
        contract.approve_verification(&user1);

        env.mock_all_auths();
        // Second user referred by first user
        let user2 = Address::generate(&env);
        contract.register_with_referral(&user2, &user1, &String::from_str(&env, "proof2"));
        contract.approve_verification(&user2);

        env.mock_all_auths();
        // Distribute rewards
        contract.distribute_rewards(&user2, &1000);

        // Check rewards
        let user1_rewards = contract.get_pending_rewards(&user1);
        assert_eq!(user1_rewards, 50); // 5% of 1000
    }

    #[test]
    fn test_milestone_achievement() {
        let env = Env::default();
        let (contract, admin, _) = test_setup::setup_contract(&env);

        env.mock_all_auths();
        // Add milestone
        let milestone = Milestone {
            required_level: UserLevel::Basic,
            requirement: MilestoneRequirement::DirectReferrals(2),
            reward_amount: 1000,
            description: String::from_str(&env, "First milestone"),
        };
        contract.add_milestone(&milestone);

        // Setup user with required referrals
        let user = Address::generate(&env);
        contract.register_with_referral(&user, &admin, &String::from_str(&env, "proof1"));
        contract.approve_verification(&user);

        // Add referrals
        for _ in 0..2 {
            let referral = Address::generate(&env);
            contract.register_with_referral(&referral, &user, &String::from_str(&env, "proof"));
        }

        // Check milestone
        contract.check_and_reward_milestone(&user);
        let user_rewards = contract.get_pending_rewards(&user);
        assert_eq!(user_rewards, 1000);
    }
}

mod test_levels {
    use super::*;

    #[test]
    fn test_level_progression() {
        let env = Env::default();
        let (contract, admin, _) = test_setup::setup_contract(&env);

        env.mock_all_auths();

        let new_requirements = LevelRequirements {
            silver: LevelCriteria {
                required_direct_referrals: 5,
                required_team_size: 5,
                required_total_rewards: 0,
            },
            gold: LevelCriteria {
                required_direct_referrals: 10,
                required_team_size: 50,
                required_total_rewards: 5000,
            },
            platinum: LevelCriteria {
                required_direct_referrals: 20,
                required_team_size: 100,
                required_total_rewards: 20000,
            },
        };
        contract.set_level_requirements(&new_requirements);

        // First user referred by admin
        let user = Address::generate(&env);
        contract.register_with_referral(&user, &admin, &String::from_str(&env, "proof1"));
        contract.approve_verification(&user);

        // Add enough referrals for Silver
        for _ in 0..6 {
            let referral = Address::generate(&env);
            contract.register_with_referral(&referral, &user, &String::from_str(&env, "proof1243"));
            contract.approve_verification(&referral);
        }

        // Check level upgrade
        let user_level = contract.get_user_level(&user);
        assert_eq!(user_level, UserLevel::Silver);
    }
}

mod test_metrics {
    use super::*;

    #[test]
    fn test_system_metrics() {
        let env = Env::default();
        let (contract, admin, _) = test_setup::setup_contract(&env);

        env.mock_all_auths();

        for _ in 0..3 {
            let user = Address::generate(&env);
            contract.register_with_referral(&user, &admin, &String::from_str(&env, "proof"));
            contract.approve_verification(&user);
        }

        // Check metrics
        let total_users = contract.get_total_users();
        assert_eq!(total_users, 4); // referrer + 3 referrals

        let conversion_rate = contract.get_referral_conversion_rate(&admin);
        assert_eq!(conversion_rate, 100); // All referrals are verified
    }
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
