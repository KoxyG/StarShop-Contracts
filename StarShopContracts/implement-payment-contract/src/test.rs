#![cfg(test)]
extern crate std;

use super::*;
use crate::transaction::TransactionContractClient;
use soroban_sdk::{
    symbol_short,
    testutils::{Address as _, AuthorizedFunction, AuthorizedInvocation, Ledger},
    token, Address, Env, IntoVal, Symbol,
};
use token::{StellarAssetClient as TokenAdmin, TokenClient};

#[test]
fn test_process_deposit_with_auth() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(TransactionContract, ());
    let contract = TransactionContractClient::new(&env, &contract_id);

    let token_admin = Address::generate(&env);

    // Create token contract
    let token_contract_id = env.register_stellar_asset_contract_v2(token_admin.clone());
    let token = TokenAdmin::new(&env, &token_contract_id.address());

    // Setup test accounts
    let sender = Address::generate(&env);
    let recipient = Address::generate(&env);

    // Mint tokens to sender
    token.mint(&sender, &1000);

    contract.process_deposit(
        &token_contract_id.address().clone(),
        &sender.clone(),
        &recipient.clone(),
        &100,
    );

    // Verify authorizations
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
        ),]
    );

    // Verify balances
    let token_client = TokenClient::new(&env, &token_contract_id.address());
    assert_eq!(token_client.balance(&sender), 900);
    assert_eq!(token_client.balance(&recipient), 100);
}

// To be implemented
// test_process_refund_with_auth()
// test_resolve_dispute_with_auth()
// test_error_conditions()
// test_cross_account_payment_execution()
