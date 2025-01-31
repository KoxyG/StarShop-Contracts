#![cfg(test)]

use super::*;
use soroban_sdk::{
    testutils::Address as _,
    token::{StellarAssetClient, TokenClient},
};

#[test]
#[should_panic(expected = "Unauthorized function call for address")]
fn test_panic_resolve_dispute_not_authenticated() {
    let env = Env::default();
    let contract_id = env.register(DisputeContract, ());
    let client = DisputeContractClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let buyer = Address::generate(&env);
    let seller = Address::generate(&env);
    let arbitrator = Address::generate(&env);
    let refund_amount = 1000i128;

    let token_contract = env.register_stellar_asset_contract_v2(admin.clone());
    let token_address = token_contract.address();

    let _token_client = TokenClient::new(&env, &token_address);
    let token_asset_client = StellarAssetClient::new(&env, &token_address);
    token_asset_client.mint(&arbitrator, &refund_amount);

    // Simulate resolving a dispute in favor of the buyer
    client.resolve_dispute(
        &token_address,
        &arbitrator,
        &buyer,
        &seller,
        &refund_amount,
        &DisputeDecision::RefundBuyer,
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #1)")]
fn test_resolve_dispute_insufficient_funds() {
    let env = Env::default();
    let contract_id = env.register(DisputeContract, ());
    let client = DisputeContractClient::new(&env, &contract_id);
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let buyer = Address::generate(&env);
    let seller = Address::generate(&env);
    let arbitrator = Address::generate(&env);
    let refund_amount = 1000i128;

    let token_contract = env.register_stellar_asset_contract_v2(admin.clone());
    let token_address = token_contract.address();

    let _token_client = TokenClient::new(&env, &token_address);
    let token_asset_client = StellarAssetClient::new(&env, &token_address);
    token_asset_client.mint(&arbitrator, &100i128);

    // Simulate resolving a dispute in favor of the buyer
    client.resolve_dispute(
        &token_address,
        &arbitrator,
        &buyer,
        &seller,
        &refund_amount,
        &DisputeDecision::RefundBuyer,
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #3)")]
fn test_resolve_dispute_invalid_amount() {
    let env = Env::default();
    let contract_id = env.register(DisputeContract, ());
    let client = DisputeContractClient::new(&env, &contract_id);
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let buyer = Address::generate(&env);
    let seller = Address::generate(&env);
    let arbitrator = Address::generate(&env);
    let invalid_refund_amount = 0i128;

    let token_contract = env.register_stellar_asset_contract_v2(admin.clone());
    let token_address = token_contract.address();

    let _token_client = TokenClient::new(&env, &token_address);
    let token_asset_client = StellarAssetClient::new(&env, &token_address);
    token_asset_client.mint(&arbitrator, &invalid_refund_amount);

    // Simulate resolving a dispute in favor of the buyer
    client.resolve_dispute(
        &token_address,
        &arbitrator,
        &buyer,
        &seller,
        &invalid_refund_amount,
        &DisputeDecision::RefundBuyer,
    );
}

#[test]
fn test_resolve_dispute_refund_buyer() {
    let env = Env::default();
    let contract_id = env.register(DisputeContract, ());
    let client = DisputeContractClient::new(&env, &contract_id);
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let buyer = <Address>::generate(&env);
    let seller = <Address>::generate(&env);
    let arbitrator = <Address>::generate(&env);
    let refund_amount = 1000i128;

    // Mock the token client for transferring tokens
    let token_contract = env.register_stellar_asset_contract_v2(admin.clone());
    let token_address = token_contract.address();

    let token_client = TokenClient::new(&env, &token_address);
    let token_asset_client = StellarAssetClient::new(&env, &token_address);
    token_asset_client.mint(&arbitrator, &refund_amount);

    let arbitrator_balance_before = token_client.balance(&arbitrator);
    assert_eq!(arbitrator_balance_before, refund_amount);

    let buyer_balance_before = token_client.balance(&buyer);
    assert_eq!(buyer_balance_before, 0);

    let seller_balance_before = token_client.balance(&seller);
    assert_eq!(seller_balance_before, 0);

    // Simulate resolving a dispute in favor of the buyer
    client.resolve_dispute(
        &token_address,
        &arbitrator,
        &buyer,
        &seller,
        &refund_amount,
        &DisputeDecision::RefundBuyer,
    );

    // Check the balance after the transfer
    let arbitrator_balance_after = token_client.balance(&arbitrator);
    assert_eq!(arbitrator_balance_after, 0);

    // Check the buyer's balance
    let buyer_balance_after = token_client.balance(&buyer);
    assert_eq!(buyer_balance_after, refund_amount);

    // Vheck the seller's balance
    let seller_balance_after = token_client.balance(&seller);
    assert_eq!(seller_balance_after, 0);
}

#[test]
fn test_resolve_dispute_pay_seller() {
    let env = Env::default();
    let contract_id = env.register(DisputeContract, ());
    let client = DisputeContractClient::new(&env, &contract_id);
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let buyer = <Address>::generate(&env);
    let seller = <Address>::generate(&env);
    let arbitrator = <Address>::generate(&env);
    let refund_amount = 1000i128;

    // Mock the token client for transferring tokens
    let token_contract = env.register_stellar_asset_contract_v2(admin.clone());
    let token_address = token_contract.address();

    let token_client = TokenClient::new(&env, &token_address);
    let token_asset_client = StellarAssetClient::new(&env, &token_address);
    token_asset_client.mint(&arbitrator, &refund_amount);

    let arbitrator_balance_before = token_client.balance(&arbitrator);
    assert_eq!(arbitrator_balance_before, refund_amount);

    let buyer_balance_before = token_client.balance(&buyer);
    assert_eq!(buyer_balance_before, 0);

    let seller_balance_before = token_client.balance(&seller);
    assert_eq!(seller_balance_before, 0);

    // Simulate resolving a dispute in favor of the buyer
    client.resolve_dispute(
        &token_address,
        &arbitrator,
        &buyer,
        &seller,
        &refund_amount,
        &DisputeDecision::PaySeller,
    );

    // Check the balance after the transfer
    let arbitrator_balance_after = token_client.balance(&arbitrator);
    assert_eq!(arbitrator_balance_after, 0);

    // Check the buyer's balance
    let buyer_balance_after = token_client.balance(&buyer);
    assert_eq!(buyer_balance_after, 0);

    // Vheck the seller's balance
    let seller_balance_after = token_client.balance(&seller);
    assert_eq!(seller_balance_after, refund_amount);
}
