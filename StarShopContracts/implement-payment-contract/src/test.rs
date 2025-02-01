#![cfg(test)]
extern crate std;

use super::*;
use crate::{
    refund::{RefundContract, RefundContractClient, RefundError},
    transaction::TransactionContractClient,
};
use soroban_sdk::{
    symbol_short,
    testutils::{Address as _, AuthorizedFunction, AuthorizedInvocation},
    token, Address, Env, IntoVal, Symbol,
};
use soroban_sdk::token::{TokenClient, StellarAssetClient as TokenAdmin};

#[test]
fn test_process_deposit_with_auth() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(TransactionContract, ());
    let client = TransactionContractClient::new(&env, &contract_id);

    let token_admin = Address::generate(&env);

    // Create token contract
    let token_contract_id = env.register_stellar_asset_contract_v2(token_admin.clone());
    let token = TokenAdmin::new(&env, &token_contract_id.address());

    // Setup test accounts
    let sender = Address::generate(&env);
    let recipient = Address::generate(&env);

    // Mint tokens to sender
    token.mint(&sender, &1000);

    // Execute transaction
    client.process_deposit(
        &token_contract_id.address().clone(),
        &sender.clone(),
        &recipient.clone(),
        &100,
    );

    // Verify signed transactions
    assert_eq!(
        env.auths(),
        std::vec![(
            sender.clone(),
            AuthorizedInvocation {
                function: AuthorizedFunction::Contract((
                    contract_id.clone(),
                    Symbol::new(&env, "process_deposit"),
                    (
                        token_contract_id.address().clone(),
                        sender.clone(),
                        recipient.clone(),
                        100_i128
                    )
                        .into_val(&env),
                )),
                sub_invocations: std::vec![AuthorizedInvocation {
                    function: AuthorizedFunction::Contract((
                        token_contract_id.address().clone(),
                        symbol_short!("transfer"),
                        (sender.clone(), recipient.clone(), 100_i128).into_val(&env),
                    )),
                    sub_invocations: std::vec![],
                }]
            }
        )]
    );

    // Verify balances
    let token_client = TokenClient::new(&env, &token_contract_id.address());
    assert_eq!(token_client.balance(&sender), 900);
    assert_eq!(token_client.balance(&recipient), 100);
}

#[test]
fn test_initialize() {
    // Create a mock environment
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(PaymentContract, ());
    let client = PaymentContractClient::new(&env, &contract_id);

    // Create an admin address
    let admin = Address::generate(&env);

    // Initialize the contract
    client.initialize(&admin);

    // Verify the admin is set correctly
    let stored_admin = client.get_admin();
    assert_eq!(stored_admin, admin, "Admin address should match");

    // Attempt to re-initialize (should fail)
    // let result = client.initialize(&admin);
    // assert_eq!(
    //     result,
    //     Err(PaymentError::AlreadyInitialized),
    //     "Re-initialization should fail"
    // );

    // assert!(
    //     matches!(result, Err(PaymentError::AlreadyInitialized)),
    //     "Re-initialization should fail with AlreadyInitialized error"
    // );
}

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

    // Verify signed transactions
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
