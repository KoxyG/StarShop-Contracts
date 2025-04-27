#![cfg(test)]

use crate::{AirdropContract, AirdropContractClient, DataKey, UserData};
use soroban_sdk::{
    Address, Env, IntoVal, String, Vec,
    testutils::{Address as _, Ledger as _, MockAuth, MockAuthInvoke},
};

// Mock token contract for testing token-based airdrops
mod mock_token {
    use soroban_sdk::{Address, Env, contract, contractimpl, token};

    #[contract]
    pub struct MockToken;

    #[contractimpl]
    impl MockToken {
        pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
            from.require_auth();
            // Simulate transfer logic
            env.events().publish(("transfer", from, to, amount));
        }

        pub fn balance(_env: Env, _addr: Address) -> i128 {
            // Mock balance for testing
            1000
        }
    }
}

fn create_test_env() -> (Env, Address, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let contract_id = env.register(AirdropContract, ());
    (env, admin, contract_id)
}

#[test]
fn test_initialize_success() {
    let (env, admin, contract_id) = create_test_env();
    let client = AirdropContractClient::new(&env, &contract_id);

    // Initialize
    client.initialize(&admin);

    // Verify storage
    let stored_admin: Address = env.storage().persistent().get(&DataKey::Admin).unwrap();
    assert_eq!(stored_admin, admin);
    let event_id: u64 = env.storage().persistent().get(&DataKey::EventId).unwrap();
    assert_eq!(event_id, 0);
}

#[test]
#[should_panic(expected = "Already initialized")]
fn test_initialize_already_initialized() {
    let (env, admin, contract_id) = create_test_env();
    let client = AirdropContractClient::new(&env, &contract_id);

    // Initialize first time
    client.initialize(&admin);

    // Attempt to initialize again
    client.initialize(&admin);
}

#[test]
fn test_record_purchase() {
    let (env, admin, contract_id) = create_test_env();
    let client = AirdropContractClient::new(&env, &contract_id);
    let user = Address::generate(&env);

    // Initialize
    client.initialize(&admin);

    // Record purchase
    client.record_purchase(&user, &100);

    // Verify user data
    let user_data: UserData = env
        .storage()
        .persistent()
        .get(&DataKey::UserData(user))
        .unwrap();
    assert_eq!(user_data.total_purchases, 100);
    assert_eq!(user_data.activity_points, 0);
    assert_eq!(user_data.loyalty_level, 0);
}

#[test]
fn test_record_activity() {
    let (env, admin, contract_id) = create_test_env();
    let client = AirdropContractClient::new(&env, &contract_id);
    let user = Address::generate(&env);

    // Initialize
    client.initialize(&admin);

    // Record activity
    client.record_activity(&user, &50);

    // Verify user data
    let user_data: UserData = env
        .storage()
        .persistent()
        .get(&DataKey::UserData(user))
        .unwrap();
    assert_eq!(user_data.total_purchases, 0);
    assert_eq!(user_data.activity_points, 50);
    assert_eq!(user_data.loyalty_level, 0);
}

#[test]
fn test_set_loyalty_level() {
    let (env, admin, contract_id) = create_test_env();
    let client = AirdropContractClient::new(&env, &contract_id);
    let user = Address::generate(&env);

    // Initialize
    client.initialize(&admin);

    // Set loyalty level
    client.set_loyalty_level(&user, &3);

    // Verify user data
    let user_data: UserData = env
        .storage()
        .persistent()
        .get(&DataKey::UserData(user))
        .unwrap();
    assert_eq!(user_data.total_purchases, 0);
    assert_eq!(user_data.activity_points, 0);
    assert_eq!(user_data.loyalty_level, 3);
}

#[test]
fn test_trigger_airdrop_xlm() {
    let (env, admin, contract_id) = create_test_env();
    let client = AirdropContractClient::new(&env, &contract_id);

    // Initialize
    client.initialize(&admin);

    // Trigger XLM airdrop
    client.trigger_airdrop(&10, &20, &1, &100, &true, &None);

    // Verify airdrop event
    let event_id: u64 = env.storage().persistent().get(&DataKey::EventId).unwrap();
    assert_eq!(event_id, 1);
    let airdrop_event: AirdropEvent = env
        .storage()
        .persistent()
        .get(&DataKey::AirdropEvent(1))
        .unwrap();
    assert_eq!(airdrop_event.min_purchases, 10);
    assert_eq!(airdrop_event.min_activity_points, 20);
    assert_eq!(airdrop_event.min_loyalty_level, 1);
    assert_eq!(airdrop_event.amount, 100);
    assert!(airdrop_event.is_xlm);
    assert!(airdrop_event.token_address.is_none());
}

#[test]
fn test_trigger_airdrop_token() {
    let (env, admin, contract_id) = create_test_env();
    let client = AirdropContractClient::new(&env, &contract_id);
    let token_address = Address::generate(&env);

    // Initialize
    client.initialize(&admin);

    // Trigger token airdrop
    client.trigger_airdrop(&10, &20, &1, &100, &false, &Some(token_address.clone()));

    // Verify airdrop event
    let event_id: u64 = env.storage().persistent().get(&DataKey::EventId).unwrap();
    assert_eq!(event_id, 1);
    let airdrop_event: AirdropEvent = env
        .storage()
        .persistent()
        .get(&DataKey::AirdropEvent(1))
        .unwrap();
    assert_eq!(airdrop_event.min_purchases, 10);
    assert_eq!(airdrop_event.min_activity_points, 20);
    assert_eq!(airdrop_event.min_loyalty_level, 1);
    assert_eq!(airdrop_event.amount, 100);
    assert!(!airdrop_event.is_xlm);
    assert_eq!(airdrop_event.token_address, Some(token_address));
}

#[test]
#[should_panic(expected = "Invalid: token_address should be None for XLM")]
fn test_trigger_airdrop_invalid_xlm() {
    let (env, admin, contract_id) = create_test_env();
    let client = AirdropContractClient::new(&env, &contract_id);
    let token_address = Address::generate(&env);

    // Initialize
    client.initialize(&admin);

    // Attempt to trigger XLM airdrop with token_address
    client.trigger_airdrop(&10, &20, &1, &100, &true, &Some(token_address));
}

#[test]
#[should_panic(expected = "Invalid: token_address required for token airdrop")]
fn test_trigger_airdrop_invalid_token() {
    let (env, admin, contract_id) = create_test_env();
    let client = AirdropContractClient::new(&env, &contract_id);

    // Initialize
    client.initialize(&admin);

    // Attempt to trigger token airdrop without token_address
    client.trigger_airdrop(&10, &20, &1, &100, &false, &None);
}

#[test]
fn test_claim_airdrop_eligible_xlm() {
    let (env, admin, contract_id) = create_test_env();
    let client = AirdropContractClient::new(&env, &contract_id);
    let user = Address::generate(&env);

    // Initialize
    client.initialize(&admin);

    // Set user data to meet eligibility
    client.record_purchase(&user, &100);
    client.record_activity(&user, &50);
    client.set_loyalty_level(&user, &2);

    // Trigger XLM airdrop
    client.trigger_airdrop(&10, &20, &1, &100, &true, &None);

    // Claim airdrop
    client.claim_airdrop(&1);

    // Verify claim status
    let claimed_key = DataKey::Claimed(1, user.clone());
    let claimed: bool = env.storage().persistent().get(&claimed_key).unwrap();
    assert!(claimed);

    // Verify XLM transfer (mocked)
    // In a real test, check balance or events
}

#[test]
fn test_claim_airdrop_eligible_token() {
    let (env, admin, contract_id) = create_test_env();
    let client = AirdropContractClient::new(&env, &contract_id);
    let user = Address::generate(&env);
    let token_address = env.register_contract_wasm(None, mock_token::MockToken);

    // Initialize
    client.initialize(&admin);

    // Set user data to meet eligibility
    client.record_purchase(&user, &100);
    client.record_activity(&user, &50);
    client.set_loyalty_level(&user, &2);

    // Trigger token airdrop
    client.trigger_airdrop(&10, &20, &1, &100, &false, &Some(token_address.clone()));

    // Claim airdrop
    client.claim_airdrop(&1);

    // Verify claim status
    let claimed_key = DataKey::Claimed(1, user.clone());
    let claimed: bool = env.storage().persistent().get(&claimed_key).unwrap();
    assert!(claimed);

    // Verify token transfer (mocked)
    // In a real test, check token balance or events
}

#[test]
#[should_panic(expected = "User not eligible")]
fn test_claim_airdrop_not_eligible() {
    let (env, admin, contract_id) = create_test_env();
    let client = AirdropContractClient::new(&env, &contract_id);
    let user = Address::generate(&env);

    // Initialize
    client.initialize(&admin);

    // Set user data to not meet eligibility
    client.record_purchase(&user, &5); // Less than min_purchases
    client.record_activity(&user, &10); // Less than min_activity_points
    client.set_loyalty_level(&user, &0); // Less than min_loyalty_level

    // Trigger airdrop
    client.trigger_airdrop(&10, &20, &1, &100, &true, &None);

    // Attempt to claim
    client.claim_airdrop(&1);
}

#[test]
#[should_panic(expected = "Already claimed")]
fn test_claim_airdrop_multiple_times() {
    let (env, admin, contract_id) = create_test_env();
    let client = AirdropContractClient::new(&env, &contract_id);
    let user = Address::generate(&env);

    // Initialize
    client.initialize(&admin);

    // Set user data to meet eligibility
    client.record_purchase(&user, &100);
    client.record_activity(&user, &50);
    client.set_loyalty_level(&user, &2);

    // Trigger airdrop
    client.trigger_airdrop(&10, &20, &1, &100, &true, &None);

    // Claim first time
    client.claim_airdrop(&1);

    // Attempt to claim again
    client.claim_airdrop(&1);
}

#[test]
#[should_panic(expected = "Airdrop event not found")]
fn test_claim_non_existent_event() {
    let (env, admin, contract_id) = create_test_env();
    let client = AirdropContractClient::new(&env, &contract_id);
    let user = Address::generate(&env);

    // Initialize
    client.initialize(&admin);

    // Attempt to claim non-existent event
    client.claim_airdrop(&999);
}

#[test]
#[should_panic(expected = "Contract not initialized")]
fn test_claim_uninitialized() {
    let (env, _admin, contract_id) = create_test_env();
    let client = AirdropContractClient::new(&env, &contract_id);
    let user = Address::generate(&env);

    // Attempt to claim without initialization
    client.claim_airdrop(&1);
}
