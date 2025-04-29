#![cfg(test)]

use super::{
    AirdropContract, AirdropContractClient,
    types::{AirdropError, AirdropEvent, DataKey, EventStats},
};
use crate::internal_finalize_event;
use soroban_sdk::{
    Address, Bytes, Env, IntoVal, Map, String, Symbol, Vec, log,
    testutils::{Address as _, Events as _, Ledger, LedgerInfo},
    token::{StellarAssetClient as TokenAdmin, TokenClient},
    vec,
};

use referral_contract::ReferralContractClient;
use referral_contract::types::RewardRates;
use referral_contract::{ReferralContract, types::UserData};

fn create_test_env() -> (Env, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let airdrop_contract = env.register(AirdropContract, ());
    (env, airdrop_contract)
}

pub fn setup_contract(e: &Env) -> (ReferralContractClient, Address, Address, Address) {
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

    (client, contract_id, admin, token.address())
}

fn setup_token(env: &Env) -> (Address, TokenAdmin) {
    let token_admin = Address::generate(env);
    let token = env.register_stellar_asset_contract_v2(token_admin.clone());
    (token.address(), TokenAdmin::new(env, &token.address()))
}

fn create_airdrop_event(
    client: &AirdropContractClient,
    admin: &Address,
    conditions: Map<Symbol, u64>,
    amount: i128,
    token_address: &Address,
) -> u64 {
    let name = Symbol::new(&client.env, "Airdrop1");
    let description = Bytes::from_slice(&client.env, b"Test airdrop");
    let start_time = client.env.ledger().timestamp();
    let end_time = start_time + 1000;

    client.create_airdrop(
        admin,
        &name,
        &description,
        &conditions,
        &amount,
        token_address,
        &start_time,
        &end_time,
        &None,
        &None,
    );

    client.env.as_contract(&client.address, || {
        client
            .env
            .storage()
            .persistent()
            .get(&DataKey::EventId)
            .unwrap()
    })
}

fn create_referral_contract(env: &Env) -> (Address, ReferralContractClient) {
    let contract_id = env.register(ReferralContract, {});
    let client = ReferralContractClient::new(env, &contract_id);
    (contract_id, client)
}

#[test]
fn test_initialize_success() {
    let (env, airdrop_contract) = create_test_env();
    let admin = Address::generate(&env);
    let providers = Some(Map::from_array(
        &env,
        [(Symbol::new(&env, "referrals"), Address::generate(&env))],
    ));

    let client = AirdropContractClient::new(&env, &airdrop_contract);

    client.initialize(&admin, &providers);

    env.as_contract(&airdrop_contract, || {
        let stored_admin: Address = env.storage().persistent().get(&DataKey::Admin).unwrap();
        let event_id: u64 = env.storage().persistent().get(&DataKey::EventId).unwrap();
        assert_eq!(stored_admin, admin);
        assert_eq!(event_id, 0);
    });
}

#[test]
fn test_initialize_already_initialized() {
    let (env, airdrop_contract) = create_test_env();
    let admin = Address::generate(&env);
    let providers = Some(Map::from_array(
        &env,
        [(Symbol::new(&env, "referrals"), Address::generate(&env))],
    ));

    let client = AirdropContractClient::new(&env, &airdrop_contract);

    client.initialize(&admin, &providers);

    let result = client.try_initialize(&admin, &providers);

    assert_eq!(result, Err(Ok(AirdropError::AlreadyInitialized)));
}

#[test]
fn test_initialize_invalid_metric_symbol() {
    let (env, airdrop_contract) = create_test_env();
    let admin = Address::generate(&env);

    // Empty symbol metric
    let providers = Some(Map::from_array(
        &env,
        [(Symbol::new(&env, ""), Address::generate(&env))],
    ));

    let client = AirdropContractClient::new(&env, &airdrop_contract);
    let result = client.try_initialize(&admin, &providers);

    assert_eq!(result, Err(Ok(AirdropError::InvalidEventConfig)));
}

#[test]
fn test_initialize_sets_provider_registry_correctly() {
    let (env, airdrop_contract) = create_test_env();
    let admin = Address::generate(&env);

    let metric = Symbol::new(&env, "referrals");
    let provider = Address::generate(&env);
    let providers = Some(Map::from_array(&env, [(metric.clone(), provider.clone())]));

    let client = AirdropContractClient::new(&env, &airdrop_contract);
    client.initialize(&admin, &providers);

    env.as_contract(&airdrop_contract, || {
        let stored: Address = env
            .storage()
            .persistent()
            .get(&DataKey::ProviderRegistry(metric.clone()))
            .unwrap();
        assert_eq!(stored, provider);
    });
}

#[test]
fn test_get_user_metric_through_referral_contract() {
    let env = Env::default();
    let (contract, _, admin, _) = setup_contract(&env);

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

    let conversion_rate = contract.get_user_metric(&user1, &Symbol::new(&env, "conversion_rate"));
    assert_eq!(conversion_rate, 75); // 3/4 verified = 75%

    let active_days = contract.get_user_metric(&user1, &Symbol::new(&env, "active_days"));
    assert_eq!(active_days, 30); // 30 days set in ledger

    let is_verified = contract.get_user_metric(&user1, &Symbol::new(&env, "is_verified"));
    assert_eq!(is_verified, 1); // User1 is verified
}

#[test]
fn airdrop_event_created() {
    let (env, airdrop_contract) = create_test_env();
    let admin = Address::generate(&env);
    let (token_address, _) = setup_token(&env);

    let client = AirdropContractClient::new(&env, &airdrop_contract);
    client.initialize(&admin, &None);

    let conditions = Map::from_array(
        &env,
        [
            (Symbol::new(&env, "referrals"), 3u64),
            (Symbol::new(&env, "is_verified"), 1u64),
        ],
    );
    let amount = 1000;
    let name = Symbol::new(&env, "Airdrop1");
    let description = Bytes::from_slice(&env, b"Test airdrop");
    let start_time = env.ledger().timestamp();
    let end_time = start_time + 1000;

    let event_id = client.create_airdrop(
        &admin,
        &name,
        &description,
        &conditions,
        &amount,
        &token_address,
        &start_time,
        &end_time,
        &None,
        &None,
    );

    env.as_contract(&airdrop_contract, || {
        let event: AirdropEvent = env
            .storage()
            .persistent()
            .get(&DataKey::AirdropEvent(event_id))
            .unwrap();
        assert_eq!(event.name, name);
        assert_eq!(event.description, description);
        assert_eq!(event.conditions, conditions);
        assert_eq!(event.amount, amount);
        assert_eq!(event.token_address, token_address);
        assert_eq!(event.start_time, start_time);
        assert_eq!(event.end_time, end_time);
        assert_eq!(event.is_active, true);

        let stats: EventStats = env
            .storage()
            .persistent()
            .get(&DataKey::EventStats(event_id))
            .unwrap();
        assert_eq!(stats.recipient_count, 0);
        assert_eq!(stats.total_amount_distributed, 0);
    });
}

#[test]
fn create_airdrop_fails_invalid_config() {
    let (env, airdrop_contract) = create_test_env();
    let admin = Address::generate(&env);
    let (token_address, _) = setup_token(&env);

    let client = AirdropContractClient::new(&env, &airdrop_contract);
    client.initialize(&admin, &None);

    let invalid_conditions = Map::new(&env); // empty
    let invalid_name = Symbol::new(&env, ""); // empty name
    let description = Bytes::from_slice(&env, b"Test airdrop");
    let now = env.ledger().timestamp();
    let end_time = now + 1000;

    let result = client.try_create_airdrop(
        &admin,
        &invalid_name,
        &description,
        &invalid_conditions,
        &0, // invalid amount
        &token_address,
        &now, // start_time now is OK, but we'll try other cases
        &end_time,
        &None,
        &None,
    );

    assert_eq!(result, Err(Ok(AirdropError::InvalidEventConfig)));
}

#[test]
fn create_airdrop_emits_created_event() {
    let (env, airdrop_contract) = create_test_env();
    let admin = Address::generate(&env);
    let (token_address, _) = setup_token(&env);
    let client = AirdropContractClient::new(&env, &airdrop_contract);

    client.initialize(&admin, &None);

    let conditions = Map::from_array(&env, [(Symbol::new(&env, "referrals"), 3u64)]);
    let amount = 1000;
    let name = Symbol::new(&env, "Drop");
    let description = Bytes::from_slice(&env, b"Test event");
    let start_time = env.ledger().timestamp();
    let end_time = start_time + 1000;

    let event_id = client.create_airdrop(
        &admin,
        &name,
        &description,
        &conditions,
        &amount,
        &token_address,
        &start_time,
        &end_time,
        &None,
        &None,
    );

    assert_eq!(
        env.events().all(),
        vec![
            &env,
            (
                airdrop_contract.clone(),
                (
                    Symbol::new(&env, "CreatedAirdropEvent"),
                    event_id,
                    admin.clone()
                )
                    .into_val(&env),
                (start_time, amount).into_val(&env)
            )
        ]
    );
}

#[test]
fn test_claim_airdrop_not_found() {
    let (env, airdrop_contract) = create_test_env();
    let admin = Address::generate(&env);
    let user = Address::generate(&env);

    let client = AirdropContractClient::new(&env, &airdrop_contract);

    client.initialize(&admin, &None);

    // Try to claim a non-existent event
    let non_existent_event_id = 999;

    env.mock_all_auths();

    let result = client.try_claim_airdrop(&user, &non_existent_event_id);

    assert_eq!(result, Err(Ok(AirdropError::AirdropNotFound)));
}

#[test]
fn test_claim_airdrop_inactive_events() {
    let (env, airdrop_contract) = create_test_env();
    let admin = Address::generate(&env);
    let user = Address::generate(&env);
    let (token_address, _) = setup_token(&env);
    let client = AirdropContractClient::new(&env, &airdrop_contract);

    client.initialize(&admin, &None);

    let conditions = Map::from_array(&env, [(Symbol::new(&env, "referrals"), 3u64)]);

    let amount = 1000;
    let name = Symbol::new(&env, "Drop");
    let description = Bytes::from_slice(&env, b"Test inactive event");
    let start_time = env.ledger().timestamp();

    let end_time = start_time + 100;

    let event_id = client.create_airdrop(
        &admin,
        &name,
        &description,
        &conditions,
        &amount,
        &token_address,
        &start_time,
        &end_time,
        &None,
        &None,
    );

    env.as_contract(&airdrop_contract, || {
        let event: AirdropEvent = env
            .storage()
            .persistent()
            .get(&DataKey::AirdropEvent(event_id))
            .unwrap();
        assert_eq!(event.is_active, true);
    });

    env.ledger().set_timestamp(start_time + 2000u64); // Move time beyond the end time

    let result = client.try_claim_airdrop(&user, &event_id);

    assert_eq!(result, Err(Ok(AirdropError::EventInactive)));

    client.finalize_event(&admin, &event_id);

    let result = client.try_claim_airdrop(&user, &event_id);

    assert_eq!(result, Err(Ok(AirdropError::EventInactive)));
}

// #[test]
// fn test_claim_airdrop_success() {
//     let (env, airdrop_contract) = create_test_env();
//     let admin = Address::generate(&env);
//     let user = Address::generate(&env);
//     let (token_address, token_admin) = setup_token(&env);

//     let client = AirdropContractClient::new(&env, &airdrop_contract);

//     // Set up a referral contract as a metric provider
//     let (referral_contract_id, _) = create_referral_contract(&env);
//     let providers = Some(Map::from_array(
//         &env,
//         [(Symbol::new(&env, "referrals"), referral_contract_id)],
//     ));

//     client.initialize(&admin, &providers);

//     // Create conditions that the user will meet
//     let conditions = Map::from_array(&env, [(Symbol::new(&env, "referrals"), 3u64)]);

//     // Fund the airdrop contract with tokens
//     token_admin.mint(&airdrop_contract, &100000);

//     // Create the airdrop event
//     let event_id = create_airdrop_event(&client, &admin, conditions, 10000, &token_address);

//     // Mock that the user meets the conditions (this depends on your implementation)
//     env.mock_all_auths();

//     // Call claim_airdrop
//     client.claim_airdrop(&user, &event_id);

//     // Verify user received tokens
//     let user_balance = TokenClient::new(&env, &token_address).balance(&user);
//     assert_eq!(user_balance, 1000);

//     // Verify event stats were updated
//     env.as_contract(&airdrop_contract, || {
//         let stats: EventStats = env
//             .storage()
//             .persistent()
//             .get(&DataKey::EventStats(event_id))
//             .unwrap();
//         assert_eq!(stats.recipient_count, 1);
//         assert_eq!(stats.total_distributed, 1000);
//     });

//     // Verify user is marked as claimed
//     env.as_contract(&airdrop_contract, || {
//         let claimed = env
//             .storage()
//             .persistent()
//             .get::<_, bool>(&DataKey::UserClaimed(event_id, user.clone()))
//             .unwrap_or(false);
//         assert_eq!(claimed, true);
//     });

//     // Verify event was emitted
//     let events = env.events().all();
//     assert!(events.iter().any(|e| {
//         match e {
//             (contract, topic, data) => {
//                 contract == &airdrop_contract
//                     && topic.contains(&Symbol::new(&env, "Claimed"))
//                     && topic.contains(&event_id)
//                     && topic.contains(&user)
//             }
//         }
//     }));
// }

// #[test]
// fn test_claim_airdrop_already_claimed() {
//     let (env, airdrop_contract) = create_test_env();
//     let admin = Address::generate(&env);
//     let user = Address::generate(&env);
//     let (token_address, token_admin) = setup_token(&env);

//     let client = AirdropContractClient::new(&env, &airdrop_contract);
//     client.initialize(&admin, &None);

//     // Create conditions
//     let conditions = Map::from_array(&env, [(Symbol::new(&env, "referrals"), 3u64)]);

//     // Fund the airdrop contract with tokens
//     token_admin.mint(&airdrop_contract, &10000);

//     // Create the airdrop event
//     let event_id = create_airdrop_event(&client, &admin, conditions, 1000, &token_address);

//     env.mock_all_auths();

//     // First claim
//     client.claim_airdrop(&user, &event_id);

//     // Second claim attempt
//     let result = client.try_claim_airdrop(&user, &event_id);

//     assert_eq!(result, Err(Ok(AirdropError::AlreadyClaimed)));
// }

// #[test]
// fn test_claim_airdrop_conditions_not_met() {
//     let (env, airdrop_contract) = create_test_env();
//     let admin = Address::generate(&env);
//     let user = Address::generate(&env);
//     let (token_address, _) = setup_token(&env);

//     // Set up a referral contract as a metric provider
//     let (referral_contract_id, referral_client) = create_referral_contract(&env);
//     let referral_admin = Address::generate(&env);
//     let token = env.register_stellar_asset_contract_v2(Address::generate(&env));

//     // Initialize the referral contract
//     referral_client.initialize(&referral_admin, &token.address());

//     let client = AirdropContractClient::new(&env, &airdrop_contract);
//     let providers = Some(Map::from_array(
//         &env,
//         [(Symbol::new(&env, "referrals"), referral_contract_id)],
//     ));

//     client.initialize(&admin, &providers);

//     // Create conditions that require 3 referrals
//     let conditions = Map::from_array(&env, [(Symbol::new(&env, "referrals"), 3u64)]);

//     // Create the airdrop event
//     let event_id = create_airdrop_event(&client, &admin, conditions, 1000, &token_address);

//     // User has 0 referrals (condition not met)
//     env.mock_all_auths();

//     let result = client.try_claim_airdrop(&user, &event_id);

//     assert_eq!(result, Err(Ok(AirdropError::UserNotEligible)));
// }

// #[test]
// fn test_claim_airdrop_max_users_exceeded() {
//     let (env, airdrop_contract) = create_test_env();
//     let admin = Address::generate(&env);
//     let user1 = Address::generate(&env);
//     let user2 = Address::generate(&env);
//     let (token_address, token_admin) = setup_token(&env);

//     let client = AirdropContractClient::new(&env, &airdrop_contract);
//     client.initialize(&admin, &None);

//     // Create conditions
//     let conditions = Map::from_array(&env, [(Symbol::new(&env, "referrals"), 3u64)]);

//     // Fund the airdrop contract with tokens
//     token_admin.mint(&airdrop_contract, &10000);

//     // Create name and description for the airdrop
//     let name = Symbol::new(&env, "Limited Airdrop");
//     let description = Bytes::from_slice(&env, b"Max 1 user");
//     let start_time = env.ledger().timestamp();
//     let end_time = start_time + 1000;

//     // Create event with max_users = 1
//     let event_id = client.create_airdrop(
//         &admin,
//         &name,
//         &description,
//         &conditions,
//         &1000,
//         &token_address,
//         &start_time,
//         &end_time,
//         &Some(1), // max_users = 1
//         &None,
//     );

//     env.mock_all_auths();

//     // First user claims successfully
//     client.claim_airdrop(&user1, &event_id);

//     // Second user should fail
//     let result = client.try_claim_airdrop(&user2, &event_id);

//     assert_eq!(result, Err(Ok(AirdropError::CapExceeded)));
// }

// #[test]
// fn test_claim_airdrop_max_total_exceeded() {
//     let (env, airdrop_contract) = create_test_env();
//     let admin = Address::generate(&env);
//     let user1 = Address::generate(&env);
//     let user2 = Address::generate(&env);
//     let (token_address, token_admin) = setup_token(&env);

//     let client = AirdropContractClient::new(&env, &airdrop_contract);
//     client.initialize(&admin, &None);

//     // Create conditions
//     let conditions = Map::from_array(&env, [(Symbol::new(&env, "referrals"), 3u64)]);

//     // Fund the airdrop contract with tokens
//     token_admin.mint(&airdrop_contract, &10000);

//     // Create name and description for the airdrop
//     let name = Symbol::new(&env, "Limited Total Airdrop");
//     let description = Bytes::from_slice(&env, b"Max 1000 total");
//     let start_time = env.ledger().timestamp();
//     let end_time = start_time + 1000;

//     // Create event with max_total = 1000
//     let event_id = client.create_airdrop(
//         &admin,
//         &name,
//         &description,
//         &conditions,
//         &1000, // 1000 per user
//         &token_address,
//         &start_time,
//         &end_time,
//         &None,
//         &Some(1000), // max_total = 1000
//     );

//     env.mock_all_auths();

//     // First user claims successfully (1000 tokens)
//     client.claim_airdrop(&user1, &event_id);

//     // Second user should fail (would exceed max total)
//     let result = client.try_claim_airdrop(&user2, &event_id);

//     assert_eq!(result, Err(Ok(AirdropError::CapExceeded)));
// }

// // #[test]
// // fn test_claim_tokens_emits_event() {
// //     let (env, airdrop_contract) = create_test_env();
// //     let admin = Address::generate(&env);
// //     let user = Address::generate(&env);
// //     let (token_address, token_admin) = setup_token(&env);

// //     let client = AirdropContractClient::new(&env, &airdrop_contract);
// //     client.initialize(&admin, &None);

// //     // Create conditions
// //     let conditions = Map::from_array(&env, [(Symbol::new(&env, "referrals"), 3u64)]);

// //     // Fund the airdrop contract with tokens
// //     token_admin.mint(&airdrop_contract, &10000);

// //     // Create airdrop with specific name for event verification
// //     let name = Symbol::new(&env, "Event Test");
// //     let description = Bytes::from_slice(&env, b"Test event emission");
// //     let start_time = env.ledger().timestamp();
// //     let end_time = start_time + 1000;

// //     let event_id = client.create_airdrop(
// //         &admin,
// //         &name,
// //         &description,
// //         &conditions,
// //         &1000,
// //         &token_address,
// //         &start_time,
// //         &end_time,
// //         &None,
// //         &None,
// //     );

// //     env.mock_all_auths();

// //     // Clear any previous events
// //     env.events().all();

// //     // Claim tokens
// //     client.claim_airdrop(&user, &event_id);

// //     // Verify event was emitted with correct data
// //     let events = env.events().all();
// //     let claim_event = events
// //         .iter()
// //         .find(|e| match e {
// //             (contract, topic, _) => {
// //                 contract == &airdrop_contract && topic.contains(&Symbol::new(&env, "Claimed"))
// //             }
// //         })
// //         .expect("Claimed event not found");

// //     // Check event details
// //     match claim_event {
// //         (_, topic, data) => {
// //             assert!(topic.contains(&Symbol::new(&env, "Claimed")));
// //             assert!(topic.contains(&event_id));
// //             assert!(topic.contains(&user));
// //             assert!(topic.contains(&name));

// //             assert!(data.contains(&token_address));
// //             assert!(data.contains(&1000));
// //             assert!(data.contains(&env.ledger().timestamp()));
// //         }
// //     }
// // }

// #[test]
// fn test_claim_airdrop_updates_stats_correctly() {
//     let (env, airdrop_contract) = create_test_env();
//     let admin = Address::generate(&env);
//     let user1 = Address::generate(&env);
//     let user2 = Address::generate(&env);
//     let (token_address, token_admin) = setup_token(&env);

//     let client = AirdropContractClient::new(&env, &airdrop_contract);
//     client.initialize(&admin, &None);

//     // Create conditions
//     let conditions = Map::from_array(&env, [(Symbol::new(&env, "referrals"), 3u64)]);

//     // Fund the airdrop contract with tokens
//     token_admin.mint(&airdrop_contract, &10000);

//     // Create the airdrop event
//     let event_id = create_airdrop_event(&client, &admin, conditions, 1000, &token_address);

//     env.mock_all_auths();

//     // First user claims
//     client.claim_airdrop(&user1, &event_id);

//     // Check stats after first claim
//     env.as_contract(&airdrop_contract, || {
//         let stats: EventStats = env
//             .storage()
//             .persistent()
//             .get(&DataKey::EventStats(event_id))
//             .unwrap();
//         assert_eq!(stats.recipient_count, 1);
//         assert_eq!(stats.total_distributed, 1000);
//     });

//     // Second user claims
//     client.claim_airdrop(&user2, &event_id);

//     // Check stats after second claim
//     env.as_contract(&airdrop_contract, || {
//         let stats: EventStats = env
//             .storage()
//             .persistent()
//             .get(&DataKey::EventStats(event_id))
//             .unwrap();
//         assert_eq!(stats.recipient_count, 2);
//         assert_eq!(stats.total_distributed, 2000);
//     });
// }

// #[test]
// fn test_claim_tokens_transfer_failure() {
//     let (env, airdrop_contract) = create_test_env();
//     let admin = Address::generate(&env);
//     let user = Address::generate(&env);
//     let (token_address, _) = setup_token(&env);

//     let client = AirdropContractClient::new(&env, &airdrop_contract);
//     client.initialize(&admin, &None);

//     // Create conditions
//     let conditions = Map::from_array(&env, [(Symbol::new(&env, "referrals"), 3u64)]);

//     // Create the airdrop event
//     let event_id = create_airdrop_event(&client, &admin, conditions, 1000, &token_address);

//     // DON'T fund the contract with tokens

//     env.mock_all_auths();

//     // Try to claim tokens - should fail due to insufficient balance
//     let result = client.try_claim_airdrop(&user, &event_id);

//     // The exact error might depend on your implementation
//     assert!(
//         result.is_err(),
//         "Should fail due to insufficient token balance"
//     );
// }

// #[test]
// fn test_event_status_override() {
//     let (env, airdrop_contract) = create_test_env();
//     let admin = Address::generate(&env);
//     let user = Address::generate(&env);
//     let (token_address, token_admin) = setup_token(&env);

//     let client = AirdropContractClient::new(&env, &airdrop_contract);
//     client.initialize(&admin, &None);

//     // Create conditions
//     let conditions = Map::from_array(&env, [(Symbol::new(&env, "referrals"), 3u64)]);

//     // Fund the airdrop contract with tokens
//     token_admin.mint(&airdrop_contract, &10000);

//     // Create the airdrop event
//     let event_id = create_airdrop_event(&client, &admin, conditions, 1000, &token_address);

//     // Set event status to inactive via storage override
//     env.as_contract(&airdrop_contract, || {
//         env.storage()
//             .persistent()
//             .set(&DataKey::EventStatus(event_id), &true);
//     });

//     env.mock_all_auths();

//     // Try to claim from inactive event
//     let result = client.try_claim_airdrop(&user, &event_id);

//     assert_eq!(result, Err(Ok(AirdropError::EventInactive)));
// }

// #[test]
// fn test_register_and_airdrop_with_referral() {
//     let (env, airdrop_contract) = create_test_env();
//     let (referral_client, referral_contract_id, admin, _) = setup_contract(&env);

//     let user1 = Address::generate(&env); // Referrer
//     let user2 = Address::generate(&env); // Referred
//     let (token_address, token_admin) = setup_token(&env);
//     let token_client = TokenClient::new(&env, &token_address);

//     let airdrop_client = AirdropContractClient::new(&env, &airdrop_contract);

//     // Initialize Referral Contract
//     referral_client.initialize(&admin, &token_address);

//     // Initialize Airdrop Contract with Referral Provider
//     let providers = Some(Map::from_array(
//         &env,
//         [(Symbol::new(&env, "referrals"), referral_contract_id.clone())],
//     ));
//     airdrop_client.initialize(&admin, &providers);

//     // Register and verify users in referral contract
//     referral_client.register_with_referral(&user1, &admin, &String::from_str(&env, "proof1"));
//     referral_client.approve_verification(&user1);
//     referral_client.register_with_referral(&user2, &user1, &String::from_str(&env, "proof2"));
//     referral_client.approve_verification(&user2);

//     // Create airdrop event
//     let conditions = Map::from_array(
//         &env,
//         [
//             (Symbol::new(&env, "referrals"), 1u64),
//             (Symbol::new(&env, "is_verified"), 1u64),
//         ],
//     );
//     let amount = 1000;
//     let event_id =
//         create_airdrop_event(&airdrop_client, &admin, conditions, amount, &token_address);

//     // Mint tokens to airdrop contract
//     token_admin.mint(&airdrop_contract, &10000);

//     // Claim airdrop for user1
//     airdrop_client.claim_airdrop(&user1, &event_id);

//     // Verify token balances and storage
//     assert_eq!(token_client.balance(&user1), 1000);
//     assert_eq!(token_client.balance(&airdrop_contract), 9000);

//     env.as_contract(&airdrop_contract, || {
//         let claimed: bool = env
//             .storage()
//             .persistent()
//             .get(&DataKey::Claimed(event_id, user1.clone()))
//             .unwrap_or(false);
//         assert!(claimed);
//         let stats: EventStats = env
//             .storage()
//             .persistent()
//             .get(&DataKey::EventStats(event_id))
//             .unwrap();
//         assert_eq!(stats.recipient_count, 1);
//         assert_eq!(stats.total_distributed, 1000);

// // Verify event emission
// let events = env.events().all();
// let last_event = events.last().unwrap();
// assert_eq!(
//     last_event.0,
//     vec![
//         &env,
//         Symbol::new(&env, "Claimed"),
//         event_id,
//         user1.clone(),
//         Symbol::new(&env, "Airdrop1")
//     ]
// );
//     });
// }

// #[test]
// fn test_trigger_airdrop_success_xlm() {
//     let (env, airdrop_contract) = create_test_env();
//     let admin = Address::generate(&env);
//     let (xlm_address, _) = setup_token(&env);

//     let client = AirdropContractClient::new(&env, &airdrop_contract);
//     client.initialize(&admin, &None);

//     let conditions = Map::from_array(
//         &env,
//         [
//             (Symbol::new(&env, "referrals"), 3u64),
//             (Symbol::new(&env, "is_verified"), 1u64),
//         ],
//     );
//     let amount = 1000;
//     let name = Symbol::new(&env, "Airdrop1");
//     let description = Bytes::from_slice(&env, b"Test airdrop");
//     let start_time = env.ledger().timestamp();
//     let end_time = start_time + 1000;

//     // Create airdrop event
//     let event_id = client.create_airdrop(
//         &admin,
//         &name,
//         &description,
//         &conditions,
//         &amount,
//         &xlm_address,
//         &start_time,
//         &end_time,
//         &None,
//         &None,
//     );

//     // Verify event creation
//     env.as_contract(&airdrop_contract, || {
//         let event: AirdropEvent = env
//             .storage()
//             .persistent()
//             .get(&DataKey::AirdropEvent(event_id))
//             .unwrap();
//         assert_eq!(event.conditions, conditions);
//         assert_eq!(event.amount, amount);
//         assert_eq!(event.token_address, xlm_address);

//         // Verify event emission
//         let events = env.events().all();
//         let last_event = events.last().unwrap();
//         assert_eq!(
//             last_event.0,
//             vec![
//                 &env,
//                 Symbol::new(&env, "CreatedAirdropEvent"),
//                 event_id,
//                 admin.clone()
//             ]
//         );
//     });
// }

// #[test]
// fn test_trigger_airdrop_success_custom_token() {
//     let (env, airdrop_contract) = create_test_env();
//     let admin = Address::generate(&env);
//     let (token_address, _) = setup_token(&env);

//     let client = AirdropContractClient::new(&env, &airdrop_contract);
//     client.initialize(&admin, &None);

//     let conditions = Map::from_array(
//         &env,
//         [
//             (Symbol::new(&env, "referrals"), 3u64),
//             (Symbol::new(&env, "is_verified"), 1u64),
//         ],
//     );
//     let amount = 500;
//     let name = Symbol::new(&env, "Airdrop1");
//     let description = Bytes::from_slice(&env, b"Test airdrop");
//     let start_time = env.ledger().timestamp();
//     let end_time = start_time + 1000;

//     // Create airdrop event
//     let event_id = client.create_airdrop(
//         &admin,
//         &name,
//         &description,
//         &conditions,
//         &amount,
//         &token_address,
//         &start_time,
//         &end_time,
//         &None,
//         &None,
//     );

//     // Verify event creation
//     env.as_contract(&airdrop_contract, || {
//         let event: AirdropEvent = env
//             .storage()
//             .persistent()
//             .get(&DataKey::AirdropEvent(event_id))
//             .unwrap();
//         assert_eq!(event.conditions, conditions);
//         assert_eq!(event.amount, amount);
//         assert_eq!(event.token_address, token_address);

//         // Verify event emission
//         let events = env.events().all();
//         let last_event = events.last().unwrap();
//         assert_eq!(
//             last_event.0,
//             vec![
//                 &env,
//                 Symbol::new(&env, "CreatedAirdropEvent"),
//                 event_id,
//                 admin.clone()
//             ]
//         );
//     });
// }

// #[test]
// fn test_claim_airdrop_not_eligible() {
//     let (env, airdrop_contract) = create_test_env();
//     let admin = Address::generate(&env);
//     let user = Address::generate(&env);
//     let (token_address, token_admin) = setup_token(&env);

//     let (referral_contract_id, referral_client) = create_referral_contract(&env);
//     let airdrop_client = AirdropContractClient::new(&env, &airdrop_contract);

//     // Setup contracts
//     referral_client.initialize(&admin, &token_address);
//     airdrop_client.initialize(&admin, &None);
//     airdrop_client.register_provider(
//         &admin,
//         &Symbol::new(&env, "referrals"),
//         &referral_contract_id,
//     );

//     // Create airdrop event with high referral requirement
//     let conditions = Map::from_array(&env, [(Symbol::new(&env, "referrals"), 3u64)]);
//     let amount = 1000;
//     let event_id =
//         create_airdrop_event(&airdrop_client, &admin, conditions, amount, &token_address);

//     // Fund the contract
//     token_admin.mint(&airdrop_contract, &10000);

//     // Register user but don't add any referrals
//     referral_client.register_with_referral(&user, &admin, &String::from_str(&env, "proof"));
//     referral_client.approve_verification(&user);

//     // Try to claim - should fail due to insufficient referrals
//     let result = airdrop_client.try_claim_airdrop(&user, &event_id);
//     assert_eq!(result, Err(Ok(AirdropError::UserNotEligible)));
// }

// #[test]
// fn test_insufficient_contract_balance() {
//     let (env, airdrop_contract) = create_test_env();
//     let admin = Address::generate(&env);
//     let user = Address::generate(&env);
//     let (token_address, token_admin) = setup_token(&env);

//     let (referral_contract_id, referral_client) = create_referral_contract(&env);
//     let airdrop_client = AirdropContractClient::new(&env, &airdrop_contract);

//     // Setup contracts
//     referral_client.initialize(&admin, &token_address);
//     airdrop_client.initialize(&admin, &None);
//     airdrop_client.register_provider(
//         &admin,
//         &Symbol::new(&env, "referrals"),
//         &referral_contract_id,
//     );

//     // Create airdrop event
//     let conditions = Map::from_array(&env, [(Symbol::new(&env, "referrals"), 1u64)]);
//     let amount = 1000;
//     let event_id =
//         create_airdrop_event(&airdrop_client, &admin, conditions, amount, &token_address);

//     // Setup user with sufficient referrals
//     referral_client.register_with_referral(&user, &admin, &String::from_str(&env, "proof"));
//     referral_client.approve_verification(&user);

//     let referred = Address::generate(&env);
//     referral_client.register_with_referral(&referred, &user, &String::from_str(&env, "proof2"));
//     referral_client.approve_verification(&referred);

//     // Fund contract with insufficient balance (less than airdrop amount)
//     token_admin.mint(&airdrop_contract, &500); // Only 500 when need 1000

//     // Try to claim - should fail due to insufficient contract balance
//     let result = airdrop_client.try_claim_airdrop(&user, &event_id);
//     assert_eq!(result, Err(Ok(AirdropError::InsufficientContractBalance)));

//     // Verify no tokens were transferred
//     let token_client = TokenClient::new(&env, &token_address);
//     assert_eq!(token_client.balance(&user), 0);
//     assert_eq!(token_client.balance(&airdrop_contract), 500);
// }

// #[test]
// fn test_claim_airdrop_already_claimed() {
//     let (env, airdrop_contract) = create_test_env();
//     let admin = Address::generate(&env);
//     let user = Address::generate(&env);
//     let (token_address, token_admin) = setup_token(&env);

//     let (referral_contract_id, referral_client) = create_referral_contract(&env);
//     let airdrop_client = AirdropContractClient::new(&env, &airdrop_contract);

//     // Setup contracts
//     referral_client.initialize(&admin, &token_address);
//     airdrop_client.initialize(&admin, &None);
//     airdrop_client.register_provider(
//         &admin,
//         &Symbol::new(&env, "referrals"),
//         &referral_contract_id,
//     );

//     // Create airdrop event with minimal requirements
//     let conditions = Map::from_array(&env, [(Symbol::new(&env, "referrals"), 1u64)]);
//     let amount = 1000;
//     let event_id =
//         create_airdrop_event(&airdrop_client, &admin, conditions, amount, &token_address);

//     // Setup eligible user
//     referral_client.register_with_referral(&user, &admin, &String::from_str(&env, "proof"));
//     referral_client.approve_verification(&user);

//     let referred = Address::generate(&env);
//     referral_client.register_with_referral(&referred, &user, &String::from_str(&env, "proof2"));
//     referral_client.approve_verification(&referred);

//     // Fund contract
//     token_admin.mint(&airdrop_contract, &10000);

//     // First claim should succeed
//     airdrop_client.claim_airdrop(&user, &event_id);

//     // Second claim should fail
//     let result = airdrop_client.try_claim_airdrop(&user, &event_id);
//     assert_eq!(result, Err(Ok(AirdropError::AlreadyClaimed)));

//     // Verify only one distribution occurred
//     let token_client = TokenClient::new(&env, &token_address);
//     assert_eq!(token_client.balance(&user), amount);

//     env.as_contract(&airdrop_contract, || {
//         let stats: EventStats = env
//             .storage()
//             .persistent()
//             .get(&DataKey::EventStats(event_id))
//             .unwrap();
//         assert_eq!(stats.recipient_count, 1);
//         //assert_eq!(stats.total_distributed, amount);
//     });
// }

// // #[test]
// // fn test_batch_distribution() {
// //     let (env, airdrop_contract) = create_test_env();
// //     let admin = Address::generate(&env);
// //     let (token_address, token_admin) = setup_token(&env);

// //     // Create 5 test users
// //     let user0 = Address::generate(&env);
// //     let user1 = Address::generate(&env);
// //     let user2 = Address::generate(&env);
// //     let user3 = Address::generate(&env);
// //     let user4 = Address::generate(&env);
// //     let users = Vec::from_array(
// //         &env,
// //         [
// //             user0.clone(),
// //             user1.clone(),
//             user2.clone(),
//             user3.clone(),
//             user4.clone(),
//         ],
//     );

//     let (referral_contract_id, referral_client) = create_referral_contract(&env);
//     let airdrop_client = AirdropContractClient::new(&env, &airdrop_contract);

//     // Setup contracts
//     referral_client.initialize(&admin, &token_address);
//     airdrop_client.initialize(&admin, &None);
//     airdrop_client.register_provider(
//         &admin,
//         &Symbol::new(&env, "referrals"),
//         &referral_contract_id,
//     );

//     // Create airdrop event requiring 1 referral
//     let conditions = Map::from_array(&env, [(Symbol::new(&env, "referrals"), 1u64)]);
//     let amount = 1000i128; // Explicit i128 type
//     let event_id =
//         create_airdrop_event(&airdrop_client, &admin, conditions, amount, &token_address);

//     // Setup referrals for eligible users (0, 1, 3, 4)
//     for user in [&user0, &user1, &user3, &user4] {
//         referral_client.register_with_referral(user, &admin, &String::from_str(&env, "proof"));
//         referral_client.approve_verification(user);

//         let referred = Address::generate(&env);
//         referral_client.register_with_referral(&referred, user, &String::from_str(&env, "proof2"));
//         referral_client.approve_verification(&referred);
//     }

//     // Setup user2 with no referrals
//     referral_client.register_with_referral(&user2, &admin, &String::from_str(&env, "proof"));
//     referral_client.approve_verification(&user2);

//     // Pre-claim for user3
//     token_admin.mint(&airdrop_contract, &amount);
//     airdrop_client.claim_airdrop(&user3, &event_id);

//     // Fund contract for batch distribution
//     token_admin.mint(&airdrop_contract, &(amount * 4));

//     // Perform batch distribution
//     airdrop_client.distribute_batch(&admin, &event_id, &users);

//     // Verify results
//     let token_client = TokenClient::new(&env, &token_address);

//     // Check balances
//     assert_eq!(token_client.balance(&user0), amount); // Eligible, received
//     assert_eq!(token_client.balance(&user1), amount); // Eligible, received
//     assert_eq!(token_client.balance(&user2), 0); // Not eligible, nothing received
//     assert_eq!(token_client.balance(&user3), amount); // Already claimed, no double payment
//     assert_eq!(token_client.balance(&user4), amount); // Eligible, received

//     // Verify event stats
//     env.as_contract(&airdrop_contract, || {
//         let stats: EventStats = env
//             .storage()
//             .persistent()
//             .get(&DataKey::EventStats(event_id))
//             .unwrap();
//         assert_eq!(stats.recipient_count, 4); // 3 from batch + 1 pre-claimed
//         assert_eq!(stats.total_distributed, amount as u64);

//         // Verify claimed status
//         let users_array = [user0, user1, user2, user3, user4];
//         for (i, user) in users_array.iter().enumerate() {
//             let claimed: bool = env
//                 .storage()
//                 .persistent()
//                 .get(&DataKey::Claimed(event_id, user.clone()))
//                 .unwrap_or(false);
//             if i == 2 {
//                 assert!(!claimed); // User 2 was not eligible
//             } else {
//                 assert!(claimed); // All others should be marked as claimed
//             }
//         }
//     });
// }
