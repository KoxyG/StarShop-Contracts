#![cfg(test)]

use super::{
    AirdropContract, AirdropContractClient, interface::TrackingOperations, types::{AirdropError, DataKey, UserData},
};
use soroban_sdk::{
    symbol_short, testutils::{Address as _, Events as _}, Address, Env, Map, Symbol, Vec,
    token::{StellarAssetClient as TokenAdmin, TokenClient},
};

fn create_test_env() -> (Env, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, AirdropContract);
    (env, contract_id)
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
    amount: u64,
    token_address: &Address,
) -> u64 {
    client.trigger_airdrop(&conditions, &amount, token_address);
    let event_id: u64 = client.env().storage().persistent().get(&DataKey::EventId).unwrap();
    event_id
}

fn set_user_metrics(
    env: &Env,
    contract_id: &Address,
    admin: &Address,
    user: &Address,
    metrics: Map<Symbol, u64>,
) {
    env.as_contract(contract_id, || {
        AirdropContract.update_user_data(env, admin, user, metrics).unwrap();
    });
}

#[test]
fn test_initialize_success() {
    let (env, contract_id) = create_test_env();
    let client = AirdropContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);

    client.initialize(&admin);

    env.as_contract(&contract_id, || {
        let stored_admin: Address = env.storage().persistent().get(&DataKey::Admin).unwrap();
        let event_id: u64 = env.storage().persistent().get(&DataKey::EventId).unwrap();
        assert_eq!(stored_admin, admin);
        assert_eq!(event_id, 0);
    });
}

#[test]
fn test_initialize_already_initialized() {
    let (env, contract_id) = create_test_env();
    let client = AirdropContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);

    client.initialize(&admin);

    let result = client.try_initialize(&admin);
    assert_eq!(result, Err(Ok(AirdropError::AlreadyInitialized)));
}

#[test]
fn test_trigger_airdrop_success_xlm() {
    let (env, contract_id) = create_test_env();
    let client = AirdropContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let (xlm_address, _) = setup_token(&env);

    client.initialize(&admin);

    let mut conditions = Map::new(&env);
    conditions.set(symbol_short!("purchases"), 5);
    conditions.set(symbol_short!("loyalty"), 3);
    let amount = 1000;

    client.trigger_airdrop(&conditions, &amount, &xlm_address);

    env.as_contract(&contract_id, || {
        let event_id: u64 = env.storage().persistent().get(&DataKey::EventId).unwrap();
        assert_eq!(event_id, 1);
        let event: super::types::AirdropEvent = env
            .storage()
            .persistent()
            .get(&DataKey::AirdropEvent(1))
            .unwrap();
        assert_eq!(event.conditions, conditions);
        assert_eq!(event.amount, amount);
        assert_eq!(event.token_address, xlm_address);

        let events = env.events().all();
        assert_eq!(events.len(), 1);
        let event = events.get_unchecked(0);
        assert_eq!(event.topics, vec![&env, symbol_short!("airdrop_triggered"), 1u64.into()]);
    });
}

#[test]
fn test_trigger_airdrop_success_custom_token() {
    let (env, contract_id) = create_test_env();
    let client = AirdropContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let (token_address, _) = setup_token(&env);

    client.initialize(&admin);

    let mut conditions = Map::new(&env);
    conditions.set(symbol_short!("activity"), 100);
    let amount = 500;

    client.trigger_airdrop(&conditions, &amount, &token_address);

    env.as_contract(&contract_id, || {
        let event_id: u64 = env.storage().persistent().get(&DataKey::EventId).unwrap();
        assert_eq!(event_id, 1);
        let event: super::types::AirdropEvent = env
            .storage()
            .persistent()
            .get(&DataKey::AirdropEvent(1))
            .unwrap();
        assert_eq!(event.conditions, conditions);
        assert_eq!(event.amount, amount);
        assert_eq!(event.token_address, token_address);
    });
}

#[test]
fn test_trigger_airdrop_invalid_amount() {
    let (env, contract_id) = create_test_env();
    let client = AirdropContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let (token_address, _) = setup_token(&env);

    client.initialize(&admin);

    let conditions = Map::new(&env);

    let result = client.try_trigger_airdrop(&conditions, &0, &token_address);
    assert_eq!(result, Err(Ok(AirdropError::InvalidAmount)));
}

#[test]
#[should_panic(expected = "Error(Contract, Unauthorized)")]
fn test_trigger_airdrop_unauthorized() {
    let (env, contract_id) = create_test_env();
    let client = AirdropContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let non_admin = Address::generate(&env);
    let (token_address, _) = setup_token(&env);

    client.initialize(&admin);

    env.as_contract(&contract_id, || {
        env.mock_all_auths_with_caller(&non_admin);
    });

    client.trigger_airdrop(&Map::new(&env), &1000, &token_address);
}

#[test]
fn test_claim_airdrop_success() {
    let (env, contract_id) = create_test_env();
    let client = AirdropContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let user = Address::generate(&env);
    let (token_address, token_admin) = setup_token(&env);
    let token_client = TokenClient::new(&env, &token_address);

    client.initialize(&admin);

    let mut conditions = Map::new(&env);
    conditions.set(symbol_short!("purchases"), 5);
    let amount = 1000;

    let event_id = create_airdrop_event(&client, &admin, conditions.clone(), amount, &token_address);

    let mut metrics = Map::new(&env);
    metrics.set(symbol_short!("purchases"), 10);
    set_user_metrics(&env, &contract_id, &admin, &user, metrics);

    token_admin.mint(&contract_id, &10000);

    client.claim_airdrop(&event_id);

    assert_eq!(token_client.balance(&user), 1000);
    assert_eq!(token_client.balance(&contract_id), 9000);

    env.as_contract(&contract_id, || {
        let claimed: bool = env
            .storage()
            .persistent()
            .get(&DataKey::Claimed(event_id, user.clone()))
            .unwrap_or(false);
        assert!(claimed);
    });

    let events = env.events().all();
    assert_eq!(events.len(), 2);
    let claimed_event = events.get_unchecked(1);
    assert_eq!(
        claimed_event.topics,
        vec![&env, symbol_short!("claimed"), event_id.into(), user.into()]
    );
    assert_eq!(claimed_event.data, (token_address, amount));
}

#[test]
fn test_claim_airdrop_not_eligible() {
    let (env, contract_id) = create_test_env();
    let client = AirdropContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let user = Address::generate(&env);
    let (token_address, _) = setup_token(&env);

    client.initialize(&admin);

    let mut conditions = Map::new(&env);
    conditions.set(symbol_short!("purchases"), 5);
    let amount = 1000;

    let event_id = create_airdrop_event(&client, &admin, conditions, amount, &token_address);

    let mut metrics = Map::new(&env);
    metrics.set(symbol_short!("purchases"), 2);
    set_user_metrics(&env, &contract_id, &admin, &user, metrics);

    let result = client.try_claim_airdrop(&event_id);
    assert_eq!(result, Err(Ok(AirdropError::UserNotEligible)));
}

#[test]
fn test_claim_airdrop_already_claimed() {
    let (env, contract_id) = create_test_env();
    let client = AirdropContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let user = Address::generate(&env);
    let (token_address, token_admin) = setup_token(&env);

    client.initialize(&admin);

    let mut conditions = Map::new(&env);
    conditions.set(symbol_short!("purchases"), 5);
    let amount = 1000;

    let event_id = create_airdrop_event(&client, &admin, conditions.clone(), amount, &token_address);

    let mut metrics = Map::new(&env);
    metrics.set(symbol_short!("purchases"), 10);
    set_user_metrics(&env, &contract_id, &admin, &user, metrics);

    token_admin.mint(&contract_id, &10000);

    client.claim_airdrop(&event_id);

    let result = client.try_claim_airdrop(&event_id);
    assert_eq!(result, Err(Ok(AirdropError::AlreadyClaimed)));
}

#[test]
fn test_claim_airdrop_invalid_event() {
    let (env, contract_id) = create_test_env();
    let client = AirdropContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let user = Address::generate(&env);

    client.initialize(&admin);

    let result = client.try_claim_airdrop(&1);
    assert_eq!(result, Err(Ok(AirdropError::AirdropNotFound)));
}

#[test]
#[should_panic(expected = "Error(Auth, InvalidAction)")]
fn test_claim_airdrop_unauthenticated() {
    let env = Env::default();
    let contract_id = env.register_contract(None, AirdropContract);
    let client = AirdropContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let user = Address::generate(&env);
    let (token_address, token_admin) = setup_token(&env);

    env.mock_all_auths();
    client.initialize(&admin);

    let mut conditions = Map::new(&env);
    conditions.set(symbol_short!("purchases"), 5);
    let amount = 1000;

    let event_id = create_airdrop_event(&client, &admin, conditions.clone(), amount, &token_address);

    let mut metrics = Map::new(&env);
    metrics.set(symbol_short!("purchases"), 10);
    set_user_metrics(&env, &contract_id, &admin, &user, metrics);

    token_admin.mint(&contract_id, &10000);

    env.mock_all_auths_with_caller(&user);
    client.claim_airdrop(&event_id);
}

#[test]
fn test_distribute_all_success() {
    let (env, contract_id) = create_test_env();
    let client = AirdropContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let (token_address, token_admin) = setup_token(&env);
    let token_client = TokenClient::new(&env, &token_address);

    let users: Vec<Address> = (0..10)
        .map(|_| Address::generate(&env))
        .collect::<Vec<_>>();

    client.initialize(&admin);

    let mut conditions = Map::new(&env);
    conditions.set(symbol_short!("purchases"), 5);
    let amount = 1000;

    let event_id = create_airdrop_event(&client, &admin, conditions.clone(), amount, &token_address);

    let mut metrics_eligible = Map::new(&env);
    metrics_eligible.set(symbol_short!("purchases"), 10);
    let mut metrics_ineligible = Map::new(&env);
    metrics_ineligible.set(symbol_short!("purchases"), 2);

    for i in 0..10 {
        let user = &users[i];
        if i < 6... (continues as before)
            set_user_metrics(&env, &contract_id, &admin, user, metrics_eligible.clone());
        } else {
            set_user_metrics(&env, &contract_id, &admin, user, metrics_ineligible.clone());
        }
    }

    token_admin.mint(&contract_id, &10000);

    client.distribute_all(&event_id, &users);

    env.as_contract(&contract_id, || {
        for i in 0..10 {
            let user = &users[i];
            let claimed: bool = env
                .storage()
                .persistent()
                .get(&DataKey::Claimed(event_id, user.clone()))
                .unwrap_or(false);
            if i < 6 {
                assert_eq!(token_client.balance(user), 1000);
                assert!(claimed);
            } else {
                assert_eq!(token_client.balance(user), 0);
                assert!(!claimed);
            }
        }
    });

    assert_eq!(token_client.balance(&contract_id), 4000);

    let events = env.events().all();
    assert_eq!(events.len(), 7);
}

#[test]
#[should_panic(expected = "Error(Contract, Unauthorized)")]
fn test_distribute_all_unauthorized() {
    let (env, contract_id) = create_test_env();
    let client = AirdropContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let non_admin = Address::generate(&env);
    let (token_address, _) = setup_token(&env);

    client.initialize(&admin);

    let conditions = Map::new(&env);
    let amount = 1000;

    let event_id = create_airdrop_event(&client, &admin, conditions, amount, &token_address);

    env.as_contract(&contract_id, || {
        env.mock_all_auths_with_caller(&non_admin);
    });
    client.distribute_all(&event_id, &Vec::new(&env));
}

#[test]
fn test_check_eligibility_success() {
    let (env, contract_id) = create_test_env();
    let client = AirdropContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let user = Address::generate(&env);
    let (token_address, _) = setup_token(&env);

    client.initialize(&admin);

    let mut conditions = Map::new(&env);
    conditions.set(symbol_short!("purchases"), 5);
    let amount = 1000;

    let event_id = create_airdrop_event(&client, &admin, conditions, amount, &token_address);

    let mut metrics = Map::new(&env);
    metrics.set(symbol_short!("purchases"), 10);
    set_user_metrics(&env, &contract_id, &admin, &user, metrics);

    env.as_contract(&contract_id, || {
        let result = AirdropContract.check_eligibility(&env, &user, event_id);
        assert!(result.is_ok());
    });
}

#[test]
fn test_check_eligibility_not_eligible() {
    let (env, contract_id) = create_test_env();
    let client = AirdropContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let user = Address::generate(&env);
    let (token_address, _) = setup_token(&env);

    client.initialize(&admin);

    let mut conditions = Map::new(&env);
    conditions.set(symbol_short!("purchases"), 5);
    let amount = 1000;

    let event_id = create_airdrop_event(&client, &admin, conditions, amount, &token_address);

    let mut metrics = Map::new(&env);
    metrics.set(symbol_short!("purchases"), 2);
    set_user_metrics(&env, &contract_id, &admin, &user, metrics);

    env.as_contract(&contract_id, || {
        let result = AirdropContract.check_eligibility(&env, &user, event_id);
        assert_eq!(result, Err(AirdropError::UserNotEligible));
    });
}

#[test]
fn test_update_user_data_success() {
    let (env, contract_id) = create_test_env();
    let client = AirdropContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let user = Address::generate(&env);

    client.initialize(&admin);

    let mut metrics = Map::new(&env);
    metrics.set(symbol_short!("purchases"), 10);
    metrics.set(symbol_short!("loyalty"), 5);

    env.as_contract(&contract_id, || {
        AirdropContract.update_user_data(&env, &admin, &user, metrics.clone()).unwrap();
    });

    env.as_contract(&contract_id, || {
        let user_data: UserData = env
            .storage()
            .persistent()
            .get(&DataKey::UserData(user.clone()))
            .unwrap();
        assert_eq!(user_data.metrics, metrics);
    });
}

#[test]
#[should_panic(expected = "Error(Contract, Unauthorized)")]
fn test_update_user_data_unauthorized() {
    let (env, contract_id) = create_test_env();
    let client = AirdropContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let non_admin = Address::generate(&env);
    let user = Address::generate(&env);

    client.initialize(&admin);

    env.as_contract(&contract_id, || {
        env.mock_all_auths_with_caller(&non_admin);
        let metrics = Map::new(&env);
        AirdropContract.update_user_data(&env, &non_admin, &user, metrics).unwrap();
    });
}

#[test]
fn test_get_user_data_default() {
    let (env, contract_id) = create_test_env();
    let client = AirdropContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let user = Address::generate(&env);

    client.initialize(&admin);

    env.as_contract(&contract_id, || {
        let user_data = AirdropContract.get_user_data(&env, &user);
        assert_eq!(user_data.metrics, Map::new(&env));
    });
}

#[test]
fn test_insufficient_contract_balance() {
    let (env, contract_id) = create_test_env();
    let client = AirdropContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let user = Address::generate(&env);
    let (token_address, _) = setup_token(&env);

    client.initialize(&admin);

    let mut conditions = Map::new(&env);
    conditions.set(symbol_short!("purchases"), 5);
    let amount = 1000;

    let event_id = create_airdrop_event(&client, &admin, conditions.clone(), amount, &token_address);

    let mut metrics = Map::new(&env);
    metrics.set(symbol_short!("purchases"), 10);
    set_user_metrics(&env, &contract_id, &admin, &user, metrics);

    let result = client.try_claim_airdrop(&event_id);
    assert_eq!(result, Err(Ok(AirdropError::InsufficientContractBalance)));
}