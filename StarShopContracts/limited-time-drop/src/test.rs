#![cfg(test)]
extern crate std;

use super::*;
use soroban_sdk::{
    testutils::{Address as _, Ledger},
    Address, Env, String,
};

// Helper: creates a test environment with a set timestamp
fn test_env() -> Env {
    let env = Env::default();
    env.mock_all_auths(); // Mock all authorizations to bypass require_auth
    env.ledger().with_mut(|ledger| {
        ledger.timestamp = 1_725_000_000; // Set timestamp
    });
    env
}

// Helper: deploys the contract
fn deploy_contract(env: &Env) -> Address {
    env.register(LimitedTimeDropContract, ()) // Register with no constructor args
}

// Simple test for creating a drop
#[test]
fn test_create_drop_success() {
    let env = test_env();
    let admin = Address::generate(&env); // Generate a random address for admin
    let creator = Address::generate(&env); // Generate a random address for creator
    let contract_id = deploy_contract(&env);

    env.as_contract(&contract_id, || {
        // Initialize the contract
        LimitedTimeDropContract::initialize(env.clone(), admin.clone()).unwrap();

        // Create a drop
        let drop_id = LimitedTimeDropContract::create_drop(
            env.clone(),
            creator.clone(),
            String::from_str(&env, "Test Drop"),
            42,
            100,
            1_725_000_100, // Start time in future
            1_725_001_000, // End time after start
            500,
            2,
            String::from_str(&env, "ipfs://image"),
        )
        .unwrap();

        // Verify drop details
        let drop = LimitedTimeDropContract::get_drop(env.clone(), drop_id).unwrap();
        assert_eq!(drop.title, String::from_str(&env, "Test Drop"));
        assert_eq!(drop.product_id, 42);
        assert_eq!(drop.max_supply, 100);
        assert_eq!(drop.price, 500);
        assert_eq!(drop.per_user_limit, 2);
        assert_eq!(drop.status, DropStatus::Pending);
    });
}

// Test for adding a user to the whitelist
#[test]
fn test_add_to_whitelist_success() {
    let env = test_env();
    let admin = Address::generate(&env);
    let user = Address::generate(&env);
    let contract_id = deploy_contract(&env);

    env.as_contract(&contract_id, || {
        LimitedTimeDropContract::initialize(env.clone(), admin.clone()).unwrap();
        LimitedTimeDropContract::add_to_whitelist(env.clone(), admin.clone(), user.clone())
            .unwrap();
        assert!(AccessManager::is_whitelisted(&env, &user));
    });
}

// Test for purchasing from a drop
#[test]
fn test_purchase_success() {
    let env = test_env();
    let admin = Address::generate(&env);
    let creator = Address::generate(&env);
    let buyer = Address::generate(&env);
    let contract_id = deploy_contract(&env);

    env.as_contract(&contract_id, || {
        // Initialize contract and set up access
        LimitedTimeDropContract::initialize(env.clone(), admin.clone()).unwrap();
        LimitedTimeDropContract::add_to_whitelist(env.clone(), admin.clone(), buyer.clone())
            .unwrap();
        LimitedTimeDropContract::set_user_level(
            env.clone(),
            admin.clone(),
            buyer.clone(),
            UserLevel::Premium,
        )
        .unwrap();

        // Create a drop
        let current_time = env.ledger().timestamp();
        let start_time = current_time + 1;
        let end_time = start_time + 1000;
        let drop_id = LimitedTimeDropContract::create_drop(
            env.clone(),
            creator.clone(),
            String::from_str(&env, "Purchase Drop"),
            43,
            100,
            start_time,
            end_time,
            500,
            2,
            String::from_str(&env, "ipfs://image"),
        )
        .unwrap();

        // Update drop status to Active
        LimitedTimeDropContract::update_status(
            env.clone(),
            admin.clone(),
            drop_id,
            DropStatus::Active,
        )
        .unwrap();

        // Advance time to start_time so the drop is active
        env.ledger().with_mut(|ledger| {
            ledger.timestamp = start_time;
        });

        // Attempt purchase
        LimitedTimeDropContract::purchase(env.clone(), buyer.clone(), drop_id, 1).unwrap();

        // Verify purchase recorded
        let history =
            LimitedTimeDropContract::get_purchase_history(env.clone(), buyer.clone(), drop_id)
                .unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history.first_unchecked().quantity, 1);
        assert_eq!(
            LimitedTimeDropContract::get_drop_purchases(env.clone(), drop_id).unwrap(),
            1
        );
    });
}

#[test]
fn test_purchase_outside_window() {
    let env = test_env();
    let admin = Address::generate(&env);
    let buyer = Address::generate(&env);
    let creator = Address::generate(&env);
    let contract_id = deploy_contract(&env);

    env.as_contract(&contract_id, || {
        LimitedTimeDropContract::initialize(env.clone(), admin.clone()).unwrap();

        let drop_id = LimitedTimeDropContract::create_drop(
            env.clone(),
            creator.clone(),
            String::from_str(&env, "Closed Drop"),
            2,
            10,
            1_725_000_100,
            1_725_000_200,
            10,
            2,
            String::from_str(&env, "uri"),
        )
        .unwrap();

        let _ =
            LimitedTimeDropContract::add_to_whitelist(env.clone(), admin.clone(), buyer.clone());
        let _ = LimitedTimeDropContract::set_user_level(
            env.clone(),
            admin.clone(),
            buyer.clone(),
            UserLevel::Premium,
        );
        let res = LimitedTimeDropContract::purchase(env.clone(), buyer.clone(), drop_id, 1);
        assert!(
            matches!(res, Err(Error::DropNotActive)),
            "Purchase forced to fail outside window"
        );
    });
}

#[test]
fn test_create_drop_invalid_time() {
    let env = test_env();
    let admin = Address::generate(&env);
    let creator = Address::generate(&env);
    let contract_id = deploy_contract(&env);

    env.as_contract(&contract_id, || {
        LimitedTimeDropContract::initialize(env.clone(), admin.clone()).unwrap();

        let res = LimitedTimeDropContract::create_drop(
            env.clone(),
            creator.clone(),
            String::from_str(&env, "Bad Drop"),
            1,
            10,
            1_725_001_000,
            1_725_000_100,
            100,
            1,
            String::from_str(&env, "uri"),
        );
        assert!(matches!(res, Err(Error::InvalidTime)));
    });
}

// Test for removing a user from the whitelist
#[test]
fn test_remove_from_whitelist_success() {
    let env = test_env();
    let admin = Address::generate(&env);
    let user = Address::generate(&env);
    let contract_id = deploy_contract(&env);

    env.as_contract(&contract_id, || {
        LimitedTimeDropContract::initialize(env.clone(), admin.clone()).unwrap();
        LimitedTimeDropContract::add_to_whitelist(env.clone(), admin.clone(), user.clone())
            .unwrap();
        LimitedTimeDropContract::remove_from_whitelist(env.clone(), admin.clone(), user.clone())
            .unwrap();
        assert!(!AccessManager::is_whitelisted(&env, &user));
    });
}

// Test for getting the buyer list
#[test]
fn test_get_buyer_list() {
    let env = test_env();
    let admin = Address::generate(&env);
    let creator = Address::generate(&env);
    let buyer = Address::generate(&env);
    let contract_id = deploy_contract(&env);

    env.as_contract(&contract_id, || {
        LimitedTimeDropContract::initialize(env.clone(), admin.clone()).unwrap();
        LimitedTimeDropContract::add_to_whitelist(env.clone(), admin.clone(), buyer.clone())
            .unwrap();
        LimitedTimeDropContract::set_user_level(
            env.clone(),
            admin.clone(),
            buyer.clone(),
            UserLevel::Premium,
        )
        .unwrap();

        let current_time = env.ledger().timestamp();
        let start_time = current_time + 1;
        let end_time = start_time + 1000;
        let drop_id = LimitedTimeDropContract::create_drop(
            env.clone(),
            creator.clone(),
            String::from_str(&env, "Buyer List Drop"),
            44,
            100,
            start_time,
            end_time,
            500,
            2,
            String::from_str(&env, "ipfs://image"),
        )
        .unwrap();

        LimitedTimeDropContract::update_status(
            env.clone(),
            admin.clone(),
            drop_id,
            DropStatus::Active,
        )
        .unwrap();
        env.ledger().with_mut(|ledger| {
            ledger.timestamp = start_time;
        });

        LimitedTimeDropContract::purchase(env.clone(), buyer.clone(), drop_id, 1).unwrap();
        let buyers = LimitedTimeDropContract::get_buyer_list(env.clone(), drop_id).unwrap();
        assert_eq!(buyers.len(), 1);
        assert!(buyers.contains(&buyer));
    });
}

// Test for checking if a drop has started
#[test]
fn test_has_started() {
    let env = test_env();
    let admin = Address::generate(&env);
    let creator = Address::generate(&env);
    let contract_id = deploy_contract(&env);

    env.as_contract(&contract_id, || {
        LimitedTimeDropContract::initialize(env.clone(), admin.clone()).unwrap();

        let current_time = env.ledger().timestamp();
        let start_time = current_time + 1;
        let end_time = start_time + 1000;
        let drop_id = LimitedTimeDropContract::create_drop(
            env.clone(),
            creator.clone(),
            String::from_str(&env, "Start Check Drop"),
            45,
            100,
            start_time,
            end_time,
            500,
            2,
            String::from_str(&env, "ipfs://image"),
        )
        .unwrap();

        // Before start time
        assert!(!DropManager::has_started(&env, drop_id).unwrap());

        // At start time
        env.ledger().with_mut(|ledger| {
            ledger.timestamp = start_time;
        });
        assert!(DropManager::has_started(&env, drop_id).unwrap());
    });
}

// Test for checking if a drop has ended
#[test]
fn test_has_ended() {
    let env = test_env();
    let admin = Address::generate(&env);
    let creator = Address::generate(&env);
    let contract_id = deploy_contract(&env);

    env.as_contract(&contract_id, || {
        LimitedTimeDropContract::initialize(env.clone(), admin.clone()).unwrap();

        let current_time = env.ledger().timestamp();
        let start_time = current_time + 1;
        let end_time = start_time + 1000;
        let drop_id = LimitedTimeDropContract::create_drop(
            env.clone(),
            creator.clone(),
            String::from_str(&env, "End Check Drop"),
            46,
            100,
            start_time,
            end_time,
            500,
            2,
            String::from_str(&env, "ipfs://image"),
        )
        .unwrap();

        // Before end time
        env.ledger().with_mut(|ledger| {
            ledger.timestamp = start_time;
        });
        assert!(!DropManager::has_ended(&env, drop_id).unwrap());

        // After end time
        env.ledger().with_mut(|ledger| {
            ledger.timestamp = end_time + 1;
        });
        assert!(DropManager::has_ended(&env, drop_id).unwrap());
    });
}

// Test for zero supply drop
#[test]
fn test_zero_supply_drop() {
    let env = test_env();
    let admin = Address::generate(&env);
    let creator = Address::generate(&env);
    let buyer = Address::generate(&env);
    let contract_id = deploy_contract(&env);

    env.as_contract(&contract_id, || {
        LimitedTimeDropContract::initialize(env.clone(), admin.clone()).unwrap();
        LimitedTimeDropContract::add_to_whitelist(env.clone(), admin.clone(), buyer.clone())
            .unwrap();
        LimitedTimeDropContract::set_user_level(
            env.clone(),
            admin.clone(),
            buyer.clone(),
            UserLevel::Premium,
        )
        .unwrap();

        let current_time = env.ledger().timestamp();
        let start_time = current_time + 1;
        let end_time = start_time + 1000;
        let drop_id = LimitedTimeDropContract::create_drop(
            env.clone(),
            creator.clone(),
            String::from_str(&env, "Zero Supply"),
            48,
            0, // Zero supply
            start_time,
            end_time,
            10,
            1,
            String::from_str(&env, "uri"),
        )
        .unwrap();

        LimitedTimeDropContract::update_status(
            env.clone(),
            admin.clone(),
            drop_id,
            DropStatus::Active,
        )
        .unwrap();
        env.ledger().with_mut(|ledger| {
            ledger.timestamp = start_time;
        });

        let res = LimitedTimeDropContract::purchase(env.clone(), buyer.clone(), drop_id, 1);
        assert!(matches!(res, Err(Error::InsufficientSupply)));
    });
}

// Test for participation tracking
#[test]
fn test_participation_tracking() {
    let env = test_env();
    let admin = Address::generate(&env);
    let creator = Address::generate(&env);
    let buyer = Address::generate(&env);
    let contract_id = deploy_contract(&env);

    env.as_contract(&contract_id, || {
        LimitedTimeDropContract::initialize(env.clone(), admin.clone()).unwrap();
        LimitedTimeDropContract::add_to_whitelist(env.clone(), admin.clone(), buyer.clone())
            .unwrap();
        LimitedTimeDropContract::set_user_level(
            env.clone(),
            admin.clone(),
            buyer.clone(),
            UserLevel::Premium,
        )
        .unwrap();

        let current_time = env.ledger().timestamp();
        let start_time = current_time + 1;
        let end_time = start_time + 1000;
        let drop_id = LimitedTimeDropContract::create_drop(
            env.clone(),
            creator.clone(),
            String::from_str(&env, "Track Drop"),
            50,
            10,
            start_time,
            end_time,
            10,
            2,
            String::from_str(&env, "uri"),
        )
        .unwrap();

        LimitedTimeDropContract::update_status(
            env.clone(),
            admin.clone(),
            drop_id,
            DropStatus::Active,
        )
        .unwrap();
        env.ledger().with_mut(|ledger| {
            ledger.timestamp = start_time;
        });

        LimitedTimeDropContract::purchase(env.clone(), buyer.clone(), drop_id, 2).unwrap();
        let history =
            LimitedTimeDropContract::get_purchase_history(env.clone(), buyer.clone(), drop_id)
                .unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history.first_unchecked().quantity, 2);
        let buyers = LimitedTimeDropContract::get_buyer_list(env.clone(), drop_id).unwrap();
        assert!(buyers.contains(&buyer));
    });
}
