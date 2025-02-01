#![cfg(test)]

use crate::follow::DEFAULT_FOLLOW_LIMIT;

use super::*;
use soroban_sdk::{testutils::Address as TestAddress, vec, Env, Vec};

#[test]
#[should_panic(expected = "Unauthorized function call for address")]
fn test_panic_follower_not_auth() {
    let env = Env::default();
    let contract_id = env.register(ProductFollowContract, ());
    let client = ProductFollowContractClient::new(&env, &contract_id);
    let follower_address = <Address>::generate(&env);

    client.follow_product(
        &follower_address,
        &3,
        &vec![&env, FollowCategory::PriceChange],
    );
}

#[test]
#[should_panic]
fn test_panic_user_already_following() {
    let env = Env::default();
    let contract_id = env.register(ProductFollowContract, ());
    let client = ProductFollowContractClient::new(&env, &contract_id);
    let follower_address = <Address>::generate(&env);
    let product_id = 3u32;
    let categories = vec![&env, FollowCategory::PriceChange];
    env.mock_all_auths();

    client.follow_product(&follower_address, &product_id, &categories);
    client.follow_product(&follower_address, &product_id, &categories);
}

#[test]
#[should_panic]
fn test_panic_follow_limit_exceeded() {
    let env = Env::default();
    let contract_id = env.register(ProductFollowContract, ());
    let client = ProductFollowContractClient::new(&env, &contract_id);
    let product_id = 3u32;
    let categories = vec![&env, FollowCategory::PriceChange];
    env.mock_all_auths();

    for _ in 0..DEFAULT_FOLLOW_LIMIT + 1 {
        let follower_address = <Address>::generate(&env);
        client.follow_product(&follower_address, &product_id, &categories);
    }
}

#[test]
fn test_add_follower() {
    let env = Env::default();
    let contract_id = env.register(ProductFollowContract, ());
    let client = ProductFollowContractClient::new(&env, &contract_id);
    let follower_address = <Address>::generate(&env);
    let product_id = 3u32;
    let categories = vec![&env, FollowCategory::PriceChange];
    env.mock_all_auths();

    client.follow_product(&follower_address, &product_id, &categories);

    env.as_contract(&contract_id, || {
        let key = symbol_short!("followers");
        let reputation_records: Vec<FollowData> = env
            .storage()
            .persistent()
            .get(&key)
            .expect("Reputation history key rating key not found");
        assert_eq!(reputation_records.len(), 1);
        assert_eq!(reputation_records.first().unwrap().user, follower_address);
        assert_eq!(reputation_records.first().unwrap().product_id, product_id);
        assert_eq!(reputation_records.first().unwrap().categories, categories);
        assert_eq!(
            reputation_records.first().unwrap().timestamp,
            env.ledger().timestamp()
        );
        assert_eq!(reputation_records.first().unwrap().expires_at, None);
    });
}

#[test]
fn test_unfollow() {
    let env = Env::default();
    let contract_id = env.register(ProductFollowContract, ());
    let followers = 5;
    let client = ProductFollowContractClient::new(&env, &contract_id);
    let product_id = 3u32;
    let categories = vec![&env, FollowCategory::PriceChange];
    let mut follower_address: Option<Address> = None;
    env.mock_all_auths();

    for _ in 0..followers {
        let follower_address = <Address>::generate(&env);
        client.follow_product(&follower_address, &product_id, &categories);
    }
    env.as_contract(&contract_id, || {
        let key = symbol_short!("followers");
        let reputation_records: Vec<FollowData> = env
            .storage()
            .persistent()
            .get(&key)
            .expect("Reputation history key rating key not found");
        assert_eq!(reputation_records.len(), followers);
        follower_address = Some(reputation_records.first().unwrap().user)
    });

    client.unfollow_product(&follower_address.unwrap(), &product_id);

    env.as_contract(&contract_id, || {
        let key = symbol_short!("followers");
        let reputation_records: Vec<FollowData> = env
            .storage()
            .persistent()
            .get(&key)
            .expect("Reputation history key rating key not found");
        assert_eq!(reputation_records.len(), followers - 1);
    });
}

#[test]
fn test_price_change_alert() {
    let env = Env::default();
    let contract_id = env.register(ProductFollowContract, ());
    let client = ProductFollowContractClient::new(&env, &contract_id);
    let product_id = 1u32;
    let new_price = 100u64;
    env.mock_all_auths();

    // Simulate following a product
    let user = Address::generate(&env);
    let categories = Vec::from_array(&env, [FollowCategory::PriceChange]);
    client.follow_product(&user, &product_id, &categories);

    // Trigger price change alert
    let result = client.try_notify_price_change(&product_id, &new_price);
    assert!(result.is_ok());

    // Verify alert was logged
    // let history = client.get_notification_history(&user);
    // assert_eq!(history.len(), 1);
    // assert_eq!(history.get(0).unwrap().event_type, FollowCategory::PriceChange);
}

#[test]
fn test_restock_alert() {
    let env = Env::default();
    let contract_id = env.register(ProductFollowContract, ());
    let client = ProductFollowContractClient::new(&env, &contract_id);
    let product_id = 1u32;
    let new_price = 100u64;
    env.mock_all_auths();

    // Simulate following a product
    let user = Address::generate(&env);
    let categories = Vec::from_array(&env, [FollowCategory::Restock]);
    client.follow_product(&user, &product_id, &categories);

    // Trigger restock alert
    let result = client.try_notify_restock(&product_id);
    assert!(result.is_ok());

    // Verify alert was logged
    let history = client.get_notification_history(&user);
   // assert_eq!(history.len(), 1);
   // assert_eq!(history.get(0).unwrap().event_type, FollowCategory::Restock);
}

#[test]
fn test_special_offer_alert() {
    let env = Env::default();
    let contract_id = env.register(ProductFollowContract, ());
    let client = ProductFollowContractClient::new(&env, &contract_id);
    let product_id = 1u32;
    let new_price = 100u64;
    env.mock_all_auths();

    // Simulate following a product
    let user = Address::generate(&env);
    let categories = Vec::from_array(&env, [FollowCategory::SpecialOffer]);
    client.follow_product(&user, &product_id, &categories);

    // Trigger special offer alert
    let result = client.try_notify_special_offer(&product_id);
    assert!(result.is_ok());

    // // Verify alert was logged
    // let history = ProductFollowContract::get_notification_history(env.clone(), user.clone()).unwrap();
    // assert_eq!(history.len(), 1);
    // assert_eq!(history.get(0).unwrap().event_type, FollowCategory::SpecialOffer);
}

#[test]
fn test_condition_combinations() {
    let env = Env::default();
    let contract_id = env.register(ProductFollowContract, ());
    let client = ProductFollowContractClient::new(&env, &contract_id);
    let product_id = 1u32;
    let new_price = 100u64;
    env.mock_all_auths();

    // Simulate following a product
    let user = Address::generate(&env);
    let categories = Vec::from_array(&env, [FollowCategory::PriceChange, FollowCategory::Restock]);
    client.follow_product(&user, &product_id, &categories);

    // Trigger price change alert
    let result = client.try_notify_price_change(&product_id, &new_price);
    assert!(result.is_ok());

    // Trigger restock alert
    let result = client.try_notify_restock(&product_id);
    assert!(result.is_ok());

    // Verify alerts were logged
    // let history = ProductFollowContract::get_notification_history(env.clone(), user.clone()).unwrap();
    // assert_eq!(history.len(), 2);
    // assert_eq!(history.get(0).unwrap().event_type, FollowCategory::PriceChange);
    // assert_eq!(history.get(1).unwrap().event_type, FollowCategory::Restock);
}

#[test]
fn test_trigger_timing() {
}
