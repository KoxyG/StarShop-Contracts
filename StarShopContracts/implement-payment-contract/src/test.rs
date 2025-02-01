#![cfg(test)]
extern crate std;

use super::*;
use crate::{
    refund::{RefundContract, RefundContractClient, RefundError},
    transaction::TransactionContractClient,
};
use soroban_sdk::token::{StellarAssetClient as TokenAdmin, TokenClient};
use soroban_sdk::{
    symbol_short,
    testutils::{Address as _, AuthorizedFunction, AuthorizedInvocation, Events},
    Address, Env, IntoVal, Symbol,
};

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
}

#[test]
#[should_panic(expected = "Error(Contract, #1)")]
fn test_get_admin_before_initialize() {
    let env = Env::default();

    let contract_id = env.register(PaymentContract, ());
    let client = PaymentContractClient::new(&env, &contract_id);

    client.get_admin();
}

#[test]
fn test_upgrade_contract() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(PaymentContract, ());
    let client = PaymentContractClient::new(&env, &contract_id);
    
    let admin = Address::generate(&env);
    
    // Initialize first
    client.initialize(&admin);
    assert_eq!(client.get_admin(), admin);

    // let contract_id = env.register_contract_wasm(None, old_contract::Wasm);

    // let client = old_contract::Client::new(&env, &contract_id);
    // let admin = Address::random(&env);
    // client.init(&admin);

    // assert_eq!(1, client.version());

    // let new_wasm_hash = install_new_wasm(&env);

    // client.upgrade(&new_wasm_hash);
    // assert_eq!(2, client.version());

    // // new_v2_fn was added in the new contract, so the existing
    // // client is out of date. Generate a new one.
    // let client = new_contract::Client::new(&env, &contract_id);
    // assert_eq!(1010101, client.new_v2_fn());
    
    // // Test upgrade
    // let new_wasm = BytesN::from_array(&env, &[9u8; 32]);
    // client.upgrade(&new_wasm.clone());

    // // Verify the upgrade event was emitted
    // let events = env.events().all();
    // assert_eq!(
    //     events.len(),
    //     2, // One event for initialization, one for upgrade
    //     "Two events should be emitted (initialization and upgrade)"
    // );

    // // Verify authorization
    // let auths = env.auths();
    // assert_eq!(auths.len(), 2);
}

#[test]
fn test_transfer_admin() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(PaymentContract, ());
    let client = PaymentContractClient::new(&env, &contract_id);
    
    let admin = Address::generate(&env);
    let new_admin = Address::generate(&env);
    
    // Initialize contract
    client.initialize(&admin);
    
    // Test admin transfer
    client.transfer_admin(&new_admin);

    // Verify authorization
    let auths = env.auths();
    assert_eq!(auths.len(), 2);
    
    // Verify new admin is set
    assert_eq!(client.get_admin(), new_admin);
}

#[test]
#[should_panic(expected = "Error(Contract, #2)")]
fn test_reinitialize() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(PaymentContract, ());
    let client = PaymentContractClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let new_admin = Address::generate(&env);

    // Create an admin address
    client.initialize(&admin);

    // Attempt to re-initialize (should fail)
    client.initialize(&new_admin);
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
