#![cfg(test)]
extern crate std;

use super::*;
use crate::{
    refund::{RefundContract, RefundContractClient, RefundError},
    transaction::TransactionContractClient,
};
use soroban_sdk::{
    symbol_short,
    testutils::{Address as _, AuthorizedFunction, AuthorizedInvocation, Ledger},
    token::{self, Client as TokenClient, StellarAssetClient as TokenAdmin},
    Address, Env, IntoVal, Symbol,
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
