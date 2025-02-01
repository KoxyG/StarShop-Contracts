#![cfg(test)]
extern crate std;

use super::*;
use soroban_sdk::{
    testutils::{Address as _, AuthorizedFunction, AuthorizedInvocation, Ledger},
    token::{self, Client as TokenClient, StellarAssetClient as TokenAdmin},
    IntoVal, Symbol,
};

#[test]
fn test_process_refund_success() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register_contract(None, RefundContract);
    let contract = RefundContractClient::new(&env, &contract_id);

    // Create token contract
    let token_admin = Address::generate(&env);
    let token_contract_id = env.register_stellar_asset_contract(token_admin.clone());

    // Clone token_contract_id to prevent move error
    let token_contract_id_clone = token_contract_id.clone();

    let token = TokenAdmin::new(&env, &token_contract_id);

    // Setup test accounts
    let seller = Address::generate(&env);
    let buyer = Address::generate(&env);

    // Mint initial tokens to seller
    token.mint(&seller, &1000);

    // Process refund
    let refund_amount = 100;
    contract.process_refund(&token_contract_id_clone, &seller, &buyer, &refund_amount);

    // Verify authorizations
    assert_eq!(
        env.auths(),
        std::vec![(
            seller.clone(),
            AuthorizedInvocation {
                function: AuthorizedFunction::Contract((
                    contract_id.clone(),
                    Symbol::new(&env, "process_refund"),
                    (
                        token_contract_id_clone.clone(),
                        seller.clone(),
                        buyer.clone(),
                        refund_amount,
                    )
                        .into_val(&env),
                )),
                sub_invocations: std::vec![AuthorizedInvocation {
                    function: AuthorizedFunction::Contract((
                        token_contract_id_clone.clone(),
                        symbol_short!("transfer"),
                        (seller.clone(), buyer.clone(), refund_amount).into_val(&env),
                    )),
                    sub_invocations: std::vec![],
                }]
            }
        )]
    );

    // Verify balances
    let token_client = TokenClient::new(&env, &token_contract_id_clone);
    assert_eq!(token_client.balance(&seller), 900);
    assert_eq!(token_client.balance(&buyer), 100);
}

#[test]
#[should_panic(expected = "Error(Contract, #4)")] // UnauthorizedAccess error
fn test_process_refund_to_self() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register_contract(None, RefundContract);
    let contract = RefundContractClient::new(&env, &contract_id);

    let token_admin = Address::generate(&env);
    let token_contract_id = env.register_stellar_asset_contract(token_admin.clone());
    let token = TokenAdmin::new(&env, &token_contract_id);

    let seller = Address::generate(&env);

    token.mint(&seller, &1000);

    contract.process_refund(&token_contract_id, &seller, &seller, &100);
}

#[test]
#[should_panic(expected = "Error(Contract, #1)")] // InsufficientFunds error
fn test_process_refund_insufficient_funds() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register_contract(None, RefundContract);
    let contract = RefundContractClient::new(&env, &contract_id);

    let token_admin = Address::generate(&env);
    let token_contract_id = env.register_stellar_asset_contract(token_admin.clone());
    let token = TokenAdmin::new(&env, &token_contract_id);

    let seller = Address::generate(&env);
    let buyer = Address::generate(&env);

    token.mint(&seller, &50);

    contract.process_refund(&token_contract_id, &seller, &buyer, &100);
}

#[test]
#[should_panic(expected = "Error(Contract, #3)")] // InvalidAmount error
fn test_process_refund_invalid_amount() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, RefundContract);
    let contract = RefundContractClient::new(&env, &contract_id);
    let token_admin = Address::generate(&env);
    let token_contract_id = env.register_stellar_asset_contract(token_admin.clone());
    let seller = Address::generate(&env);
    let buyer = Address::generate(&env);
    contract.process_refund(&token_contract_id, &seller, &buyer, &0);
}

#[test]
#[should_panic(expected = "Unauthorized function call for address")]
fn test_panic_resolve_dispute_not_authenticated() {
    // Initialize the environment and contract
    let env = Env::default();
    let contract_id = env.register(DisputeContract, ());
    let client = DisputeContractClient::new(&env, &contract_id);

    // Generate test addresses for different roles
    let admin = Address::generate(&env);
    let buyer = Address::generate(&env);
    let seller = Address::generate(&env);
    let arbitrator = Address::generate(&env);
    let refund_amount = 1000i128;

    // Set up the token contract and mint tokens to arbitrator
    let token_contract = env.register_stellar_asset_contract_v2(admin.clone());
    let token_address = token_contract.address();

    let _token_client = TokenClient::new(&env, &token_address);
    let token_asset_client = TokenAdmin::new(&env, &token_address);
    token_asset_client.mint(&arbitrator, &refund_amount);

    // This should fail because we haven't mocked the authentication
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
    // Initialize environment with mocked authentication
    let env = Env::default();
    let contract_id = env.register(DisputeContract, ());
    let client = DisputeContractClient::new(&env, &contract_id);
    env.mock_all_auths();

    // Set up test addresses and amounts
    let admin = Address::generate(&env);
    let buyer = Address::generate(&env);
    let seller = Address::generate(&env);
    let arbitrator = Address::generate(&env);
    let refund_amount = 1000i128; // Trying to refund 1000 tokens

    // Set up token contract
    let token_contract = env.register_stellar_asset_contract_v2(admin.clone());
    let token_address = token_contract.address();
    let _token_client = TokenClient::new(&env, &token_address);
    let token_asset_client = TokenAdmin::new(&env, &token_address);

    // Mint only 100 tokens - less than the refund amount
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
    // Initialize environment with mocked authentication
    let env = Env::default();
    let contract_id = env.register(DisputeContract, ());
    let client = DisputeContractClient::new(&env, &contract_id);
    env.mock_all_auths();

    // Set up test addresses
    let admin = Address::generate(&env);
    let buyer = Address::generate(&env);
    let seller = Address::generate(&env);
    let arbitrator = Address::generate(&env);
    let invalid_refund_amount = 0i128; // Invalid amount (zero)

    // Set up token contract
    let token_contract = env.register_stellar_asset_contract_v2(admin.clone());
    let token_address = token_contract.address();

    let _token_client = TokenClient::new(&env, &token_address);
    let token_asset_client = TokenAdmin::new(&env, &token_address);
    token_asset_client.mint(&arbitrator, &invalid_refund_amount);

    // This should fail due to invalid amount (zero)
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
    // Initialize environment with mocked authentication
    let env = Env::default();
    let contract_id = env.register(DisputeContract, ());
    let client = DisputeContractClient::new(&env, &contract_id);
    env.mock_all_auths();

    // Set up test addresses and amount
    let admin = Address::generate(&env);
    let buyer = <Address>::generate(&env);
    let seller = <Address>::generate(&env);
    let arbitrator = <Address>::generate(&env);
    let refund_amount = 1000i128;

    // Mock the token client for transferring tokens
    let token_contract = env.register_stellar_asset_contract_v2(admin.clone());
    let token_address = token_contract.address();

    let token_client = TokenClient::new(&env, &token_address);
    let token_asset_client = TokenAdmin::new(&env, &token_address);
    token_asset_client.mint(&arbitrator, &refund_amount);

    // Verify initial balances
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

    // Check the seller's balance
    let seller_balance_after = token_client.balance(&seller);
    assert_eq!(seller_balance_after, 0);
}

#[test]
fn test_resolve_dispute_pay_seller() {
    // Initialize environment with mocked authentication
    let env = Env::default();
    let contract_id = env.register(DisputeContract, ());
    let client = DisputeContractClient::new(&env, &contract_id);
    env.mock_all_auths();

    // Set up test addresses and amount
    let admin = Address::generate(&env);
    let buyer = <Address>::generate(&env);
    let seller = <Address>::generate(&env);
    let arbitrator = <Address>::generate(&env);
    let refund_amount = 1000i128;

    // Mock the token client for transferring tokens
    let token_contract = env.register_stellar_asset_contract_v2(admin.clone());
    let token_address = token_contract.address();

    let token_client = TokenClient::new(&env, &token_address);
    let token_asset_client = TokenAdmin::new(&env, &token_address);
    token_asset_client.mint(&arbitrator, &refund_amount);

    // Verify initial balances
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

    // Check the seller's balance
    let seller_balance_after = token_client.balance(&seller);
    assert_eq!(seller_balance_after, refund_amount);
}
