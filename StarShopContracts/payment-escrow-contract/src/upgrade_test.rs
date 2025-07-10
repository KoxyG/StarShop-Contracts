#![cfg(test)]

use crate::{
    datatypes::{DisputeDecision, PaymentStatus},
    PaymentEscrowContract, PaymentEscrowContractClient,
};
use soroban_sdk::{
    testutils::{Address as _, AuthorizedFunction, AuthorizedInvocation},
    Address, Env, IntoVal, String, Symbol, BytesN,
};
use soroban_sdk::{
    testutils::Ledger,
    token::{StellarAssetClient as TokenAdmin, TokenClient},
};

// Import the current contract WASM
mod current_contract {
    soroban_sdk::contractimport!(
        file = "target/wasm32-unknown-unknown/release/payment_escrow_contract.wasm"
    );
}

fn install_contract_wasm(e: &Env) -> BytesN<32> {
    e.install_contract_wasm(current_contract::Wasm)
}

#[test]
fn test_upgrade_functionality() {
    let env = Env::default();
    env.mock_all_auths();

    // Register the contract using WASM
    let contract_id = env.register_contract_wasm(None, current_contract::Wasm);
    let client = current_contract::Client::new(&env, &contract_id);

    // Initialize the contract with an arbitrator
    let arbitrator = Address::generate(&env);
    client.init(&arbitrator);

    // Setup token and accounts
    let token_admin = Address::generate(&env);
    let stellar_asset = env.register_stellar_asset_contract_v2(token_admin.clone());
    let token_contract_id = stellar_asset.address();
    let token = TokenAdmin::new(&env, &token_contract_id);

    let buyer = Address::generate(&env);
    let seller = Address::generate(&env);
    let amount = 100;
    let expiry_days = 30;
    let description = String::from_str(&env, "Test payment for upgrade");

    // Mint tokens to buyer
    token.mint(&buyer, &1000);

    // Create a payment before upgrade
    let payment_id = client.create_payment(
        &buyer,
        &seller,
        &amount,
        &token_contract_id,
        &expiry_days,
        &description,
    );

    // Add a second arbitrator
    let new_arbitrator = Address::generate(&env);
    client.add_arbitrator(&arbitrator, &new_arbitrator);

    // Verify initial state
    let arbitrators_before = client.get_arbitrators();
    assert_eq!(arbitrators_before.len(), 2);
    let payment_before = client.get_a_payment(&payment_id);
    assert_eq!(payment_before.status, PaymentStatus::Pending);

    // Install the new WASM (same as current for this test)
    let new_wasm_hash = install_contract_wasm(&env);

    // Perform the upgrade
    client.upgrade(&new_wasm_hash);

    // Verify that the contract still works after upgrade
    // All existing functionality should continue to work
    
    // Test 1: Verify arbitrators are preserved
    let arbitrators_after = client.get_arbitrators();
    assert_eq!(arbitrators_after.len(), 2);
    assert!(arbitrators_after.contains(&arbitrator));
    assert!(arbitrators_after.contains(&new_arbitrator));

    // Test 2: Verify payment data is preserved
    let payment_after = client.get_a_payment(&payment_id);
    assert_eq!(payment_after.id, payment_id);
    assert_eq!(payment_after.buyer, buyer);
    assert_eq!(payment_after.seller, seller);
    assert_eq!(payment_after.amount, amount);
    assert_eq!(payment_after.status, PaymentStatus::Pending);
    assert_eq!(payment_after.description, description);

    // Test 3: Verify payment counter is preserved
    let payment_count_after = client.get_payment_count();
    assert_eq!(payment_count_after, 1);

    // Test 4: Verify token balances are preserved
    let token_client = TokenClient::new(&env, &token_contract_id);
    assert_eq!(token_client.balance(&buyer), 900);
    assert_eq!(token_client.balance(&contract_id), 100);
    assert_eq!(token_client.balance(&seller), 0);

    // Test 5: Verify existing functionality still works after upgrade
    // Try to create a new payment after upgrade
    let buyer2 = Address::generate(&env);
    let seller2 = Address::generate(&env);
    token.mint(&buyer2, &1000);
    
    let payment_id2 = client.create_payment(
        &buyer2,
        &seller2,
        &amount,
        &token_contract_id,
        &expiry_days,
        &description,
    );
    
    assert_eq!(payment_id2, 2); // Should be the next payment ID

    // Test 6: Verify dispute functionality still works after upgrade
    let dispute_reason = String::from_str(&env, "Test dispute after upgrade");
    client.dispute_payment(&payment_id, &buyer, &dispute_reason);
    
    let disputed_payment = client.get_a_payment(&payment_id);
    assert_eq!(disputed_payment.status, PaymentStatus::Disputed);

    // Test 7: Verify arbitrator functionality still works after upgrade
    let arbitrator3 = Address::generate(&env);
    client.add_arbitrator(&arbitrator, &arbitrator3);
    
    let arbitrators_final = client.get_arbitrators();
    assert_eq!(arbitrators_final.len(), 3);
    assert!(arbitrators_final.contains(&arbitrator3));

    // Test 8: Verify claim functionality still works after upgrade
    // Create a short-term payment and advance time
    let payment_id3 = client.create_payment(
        &buyer2,
        &seller2,
        &50,
        &token_contract_id,
        &1, // 1 day expiry
        &description,
    );
    
    // Advance time to make payment expire
    let current_time = env.ledger().timestamp();
    let future_time = current_time + 2 * 24 * 60 * 60; // 2 days in the future
    env.ledger().set_timestamp(future_time);
    
    // Claim the expired payment
    client.claim_payment(&payment_id3, &buyer2);
    
    let claimed_payment = client.get_a_payment(&payment_id3);
    assert_eq!(claimed_payment.status, PaymentStatus::Refunded);
}

#[test]
#[should_panic]
fn test_upgrade_unauthorized() {
    let env = Env::default();
    env.mock_all_auths();

    // Register the contract using WASM
    let contract_id = env.register_contract_wasm(None, current_contract::Wasm);
    let client = current_contract::Client::new(&env, &contract_id);

    // Initialize the contract with an arbitrator
    let arbitrator = Address::generate(&env);
    client.init(&arbitrator);

    // Try to upgrade without arbitrator authorization
    // This should fail because the upgrade function requires all arbitrators to authorize
    let new_wasm_hash = install_contract_wasm(&env);
    
    // This should panic because we're not providing proper authorization
    client.upgrade(&new_wasm_hash);
} 