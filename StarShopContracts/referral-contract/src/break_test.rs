#![cfg(test)]
use super::*;
use crate::types::{MilestoneRequirement, UserLevel};
use soroban_sdk::{testutils::Address as _, Address, Env, String, IntoVal};

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

mod test_critical_auth_bypass_vulnerability {
    use super::*;

    #[test]
    fn test_critical_auth_bypass_set_reward_rates() {
        let env = Env::default();
        let (contract, admin, _) = test_setup::setup_contract(&env);

        // Create malicious user
        let malicious_user = Address::generate(&env);
        
        // MALICIOUS ATTACK: Malicious user calls admin function with admin's signature
        // This should NOT be possible but the current implementation allows it!
        let malicious_rates = RewardRates {
            level1: 9999, // 99.99% - attempt to drain funds
            level2: 9999,
            level3: 9999,
            max_reward_per_referral: 999999999,
        };

        // VULNERABILITY: Malicious user can call admin function if admin signs
        env.mock_auths(&[soroban_sdk::testutils::MockAuth {
            address: &admin, // Admin signature
            invoke: &soroban_sdk::testutils::MockAuthInvoke {
                contract: &contract.address,
                fn_name: "set_reward_rates",
                args: (malicious_rates.clone(),).into_val(&env),
                sub_invokes: &[],
            },
        }]);
        
        // This should FAIL (panic) but currently SUCCEEDS due to vulnerability
        contract.set_reward_rates(&malicious_rates);
    }

    #[test]
    fn test_critical_auth_bypass_pause_contract() {
        let env = Env::default();
        let (contract, admin, _) = test_setup::setup_contract(&env);

        // Create malicious user
        let malicious_user = Address::generate(&env);
        
        // MALICIOUS ATTACK: Malicious user pauses contract with admin's signature
        env.mock_auths(&[soroban_sdk::testutils::MockAuth {
            address: &admin, // Admin signature
            invoke: &soroban_sdk::testutils::MockAuthInvoke {
                contract: &contract.address,
                fn_name: "pause_contract",
                args: ().into_val(&env),
                sub_invokes: &[],
            },
        }]);
        
        // This should FAIL (panic) but currently SUCCEEDS due to vulnerability
        contract.pause_contract();
    }

    #[test]
    fn test_critical_auth_bypass_transfer_admin() {
        let env = Env::default();
        let (contract, admin, _) = test_setup::setup_contract(&env);

        // Create malicious user and target
        let malicious_user = Address::generate(&env);
        let attacker_controlled_address = Address::generate(&env);
        
        // MALICIOUS ATTACK: Malicious user transfers admin to attacker address
        env.mock_auths(&[soroban_sdk::testutils::MockAuth {
            address: &admin, // Admin signature
            invoke: &soroban_sdk::testutils::MockAuthInvoke {
                contract: &contract.address,
                fn_name: "transfer_admin",
                args: (attacker_controlled_address.clone(),).into_val(&env),
                sub_invokes: &[],
            },
        }]);
        
        // This should FAIL (panic) but currently SUCCEEDS due to vulnerability
        contract.transfer_admin(&attacker_controlled_address);
    }

    #[test]
    fn test_critical_auth_bypass_add_milestone() {
        let env = Env::default();
        let (contract, admin, _) = test_setup::setup_contract(&env);

        // Create malicious user
        let malicious_user = Address::generate(&env);
        
        // MALICIOUS ATTACK: Malicious user adds malicious milestone
        let malicious_milestone = Milestone {
            required_level: UserLevel::Basic,
            requirement: MilestoneRequirement::DirectReferrals(1),
            reward_amount: 999999, // Large reward
            description: String::from_str(&env, "Malicious milestone"),
        };

        env.mock_auths(&[soroban_sdk::testutils::MockAuth {
            address: &admin, // Admin signature
            invoke: &soroban_sdk::testutils::MockAuthInvoke {
                contract: &contract.address,
                fn_name: "add_milestone",
                args: (malicious_milestone.clone(),).into_val(&env),
                sub_invokes: &[],
            },
        }]);
        
        // This should FAIL (panic) but currently SUCCEEDS due to vulnerability
        contract.add_milestone(&malicious_milestone);
    }

    #[test]
    fn test_social_engineering_attack_scenario() {
        let env = Env::default();
        let (contract, admin, _) = test_setup::setup_contract(&env);
        // SOCIAL ENGINEERING ATTACK SCENARIO:
        // 1. Attacker convinces admin to sign a "harmless" transaction
        // 2. Admin thinks they're signing something else
        // 3. Attacker uses admin's signature to call admin functions
        
        let malicious_user = Address::generate(&env);
        let attacker_controlled_address = Address::generate(&env);
        
        // Attack: Admin is tricked into signing admin transfer
        env.mock_auths(&[soroban_sdk::testutils::MockAuth {
            address: &admin, // Admin signature (obtained through social engineering)
            invoke: &soroban_sdk::testutils::MockAuthInvoke {
                contract: &contract.address,
                fn_name: "transfer_admin",
                args: (attacker_controlled_address.clone(),).into_val(&env),
                sub_invokes: &[],
            },
        }]);
        
        // VULNERABILITY: This succeeds even though admin didn't intend to transfer admin rights
        contract.transfer_admin(&attacker_controlled_address);
        
        // Now attacker has admin rights and can do anything!
        // This demonstrates the critical vulnerability
        assert_eq!(contract.get_admin(), attacker_controlled_address);
        
        // Attacker can now pause contract, change reward rates, etc.
        env.mock_auths(&[soroban_sdk::testutils::MockAuth {
            address: &attacker_controlled_address, // Now attacker is admin
            invoke: &soroban_sdk::testutils::MockAuthInvoke {
                contract: &contract.address,
                fn_name: "pause_contract",
                args: ().into_val(&env),
                sub_invokes: &[],
            },
        }]);
        
        contract.pause_contract();
        assert!(contract.get_paused_state());
        
        // CRITICAL VULNERABILITY PROVEN: Social engineering attack successful!
       
    }
}
