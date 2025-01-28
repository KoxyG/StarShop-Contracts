#![cfg(test)]
use super::*;
use soroban_sdk::{
    symbol_short,
    testutils::{Address as _, Ledger, LedgerInfo},
    vec, Address, Env,
};

fn create_test_env() -> Env {
    let env = Env::default();
    // Set a valid timestamp
    env.ledger().set(LedgerInfo {
        timestamp: 12345,
        protocol_version: 20,
        sequence_number: 100,
        network_id: Default::default(),
        base_reserve: 10,
        min_temp_entry_ttl: 10,
        min_persistent_entry_ttl: 10,
        max_entry_ttl: 3110400,
    });
    env
}

#[test]
fn test_product_creation() {
    let env = create_test_env();
    let contract_id = env.register_contract(None, ProductVoting);
    let client = ProductVotingClient::new(&env, &contract_id);

    // Initialize contract
    client.init();

    // Create a product
    let product_id = symbol_short!("test");
    let product_name = symbol_short!("Test Product");
    assert!(client.create_product(&product_id, &product_name).is_ok());
}

#[test]
fn test_voting_