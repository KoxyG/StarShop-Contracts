#![cfg(test)]

use crate::follow::DEFAULT_FOLLOW_LIMIT;

use super::*;
use crate::datatype::{DataKeys, FollowCategory, FollowData};
use soroban_sdk::{
    testutils::{Address as TestAddress, Ledger as TestLedger},
    vec, Env, Vec,
};

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

    // Follow the product until the limit is reached
    for _i in 0..DEFAULT_FOLLOW_LIMIT {
        let address = <Address>::generate(&env);
        client.follow_product(&address, &product_id, &categories);
    }

    // Attempt to follow the product again, which should exceed the limit and panic
    let address = <Address>::generate(&env);
    client.follow_product(&address, &product_id, &categories);
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
        let key = DataKeys::FollowList(follower_address.clone());
        let followers: Vec<FollowData> = env
            .storage()
            .persistent()
            .get(&key)
            .expect("Follow list key not found");
        assert_eq!(followers.len(), 1);
        assert_eq!(followers.first().unwrap().user, follower_address);
        assert_eq!(followers.first().unwrap().product_id, product_id);
        assert_eq!(followers.first().unwrap().categories, categories);
        assert_eq!(
            followers.first().unwrap().timestamp,
            env.ledger().timestamp()
        );
        assert_eq!(followers.first().unwrap().expires_at, None);
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
        let address = <Address>::generate(&env);
        client.follow_product(&address, &product_id, &categories);
        if follower_address.is_none() {
            follower_address = Some(address.clone());
        }
    }

    env.as_contract(&contract_id, || {
        let key = DataKeys::FollowList(follower_address.clone().unwrap());
        let follow_records: Vec<FollowData> = env
            .storage()
            .persistent()
            .get(&key)
            .expect("Follow list key not found");
        assert_eq!(follow_records.len(), 1);
    });

    client.unfollow_product(&follower_address.clone().unwrap(), &product_id);

    env.as_contract(&contract_id, || {
        let key = DataKeys::FollowList(follower_address.clone().unwrap());
        let follow_records: Vec<FollowData> = env
            .storage()
            .persistent()
            .get(&key)
            .unwrap_or_else(|| Vec::new(&env));
        assert_eq!(follow_records.len(), 0);
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

    // Set the current time for testing purposes
    env.ledger().set_timestamp(3601);

    // Simulate following a product
    let user = Address::generate(&env);
    let categories = Vec::from_array(&env, [FollowCategory::PriceChange]);
    client.follow_product(&user, &product_id, &categories);

    // Trigger price change alert
    let result = client.try_notify_price_change(&product_id, &new_price);
    assert!(result.is_ok());

    // Verify alert was logged
    let history = client.get_notification_history(&user);

    assert_eq!(history.len(), 1);
    assert_eq!(
        history.get(0).unwrap().event_type,
        FollowCategory::PriceChange
    );
}

#[test]
fn test_restock_alert() {
    let env = Env::default();
    let contract_id = env.register(ProductFollowContract, ());
    let client = ProductFollowContractClient::new(&env, &contract_id);
    let product_id = 1u32;
    env.mock_all_auths();

    // Set the current time for testing purposes
    env.ledger().set_timestamp(3601);

    // Simulate following a product
    let user = Address::generate(&env);
    let categories = Vec::from_array(&env, [FollowCategory::Restock]);
    client.follow_product(&user, &product_id, &categories);

    // Trigger restock alert
    let result = client.try_notify_restock(&product_id);
    assert!(result.is_ok());

    // Verify alert was logged
    let history = client.get_notification_history(&user);
    assert_eq!(history.len(), 1);
    assert_eq!(history.get(0).unwrap().event_type, FollowCategory::Restock);
}

#[test]
fn test_special_offer_alert() {
    let env = Env::default();
    let contract_id = env.register(ProductFollowContract, ());
    let client = ProductFollowContractClient::new(&env, &contract_id);
    let product_id = 1u32;
    env.mock_all_auths();

    // Set the current time for testing purposes
    env.ledger().set_timestamp(3601);

    // Simulate following a product
    let user = Address::generate(&env);
    let categories = Vec::from_array(&env, [FollowCategory::SpecialOffer]);
    client.follow_product(&user, &product_id, &categories);

    // Trigger special offer alert
    let result = client.try_notify_special_offer(&product_id);
    assert!(result.is_ok());

    // // Verify alert was logged
    let history = client.get_notification_history(&user);
    assert_eq!(history.len(), 1);
    assert_eq!(
        history.get(0).unwrap().event_type,
        FollowCategory::SpecialOffer
    );
}

#[test]
fn test_condition_combinations() {
    let env = Env::default();
    let contract_id = env.register(ProductFollowContract, ());
    let client = ProductFollowContractClient::new(&env, &contract_id);
    let product_id = 1u32;
    let new_price = 100u64;
    env.mock_all_auths();

    // Set the current time for testing purposes
    env.ledger().set_timestamp(3601);

    // Simulate following a product
    let user = Address::generate(&env);
    let categories = Vec::from_array(&env, [FollowCategory::PriceChange, FollowCategory::Restock]);
    client.follow_product(&user, &product_id, &categories);

    // Trigger price change alert
    let result = client.try_notify_price_change(&product_id, &new_price);
    assert!(result.is_ok());

    // Set the current time for testing purposes
    env.ledger().set_timestamp(3601 + 3601);

    // Trigger restock alert
    let result = client.try_notify_restock(&product_id);
    assert!(result.is_ok());

    // Verify alerts were logged
    let history = client.get_notification_history(&user);
    assert_eq!(history.len(), 2);
    assert_eq!(
        history.get(0).unwrap().event_type,
        FollowCategory::PriceChange
    );
    assert_eq!(history.get(1).unwrap().event_type, FollowCategory::Restock);
}

#[test]
fn test_alert_rate_limiting() {
    let env = Env::default();
    let contract_id = env.register(ProductFollowContract, ());
    let client = ProductFollowContractClient::new(&env, &contract_id);
    let product_id = 1u32;
    let new_price = 100u64;
    env.mock_all_auths();

    // Set the current time for testing purposes
    env.ledger().set_timestamp(3601);

    // Simulate following a product
    let user = Address::generate(&env);
    let categories = Vec::from_array(&env, [FollowCategory::PriceChange]);
    client.follow_product(&user, &product_id, &categories);

    // Trigger price change alert
    let result = client.try_notify_price_change(&product_id, &new_price);
    assert!(result.is_ok());

    // Set the current time for testing purposes
    env.ledger().set_timestamp(0);

    // Attempt to trigger another price change alert within the rate limit period
    let result = client.try_notify_price_change(&product_id, &new_price);
    assert!(result.is_err());

    // Verify only one alert was logged
    let history = client.get_notification_history(&user);
    assert_eq!(history.len(), 1);
    assert_eq!(
        history.get(0).unwrap().event_type,
        FollowCategory::PriceChange
    );
}
