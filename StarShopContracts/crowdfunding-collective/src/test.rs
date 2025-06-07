#![cfg(test)]

use super::*; // Imports items from lib.rs (contract, types, etc.)
use soroban_sdk::{
    testutils::{Address as _, Ledger, MockAuth, MockAuthInvoke, LedgerInfo},
    Address, 
    Env, 
    String, 
    Vec,
    vec, // soroban_sdk::vec macro
    IntoVal, // For converting values for mock auth args
};

// Helper struct for setting up tests
struct CrowdfundingTest<'a> {
    env: Env,
    contract_id: Address,
    client: CrowdfundingCollectiveClient<'a>,
    creator: Address,
    contributor1: Address,
    contributor2: Address,
}

impl<'a> CrowdfundingTest<'a> {
    fn setup() -> Self {
        let env = Env::default();

        let contract_id = env.register(CrowdfundingCollective, ());
        let client = CrowdfundingCollectiveClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let creator = Address::generate(&env);
        let contributor1 = Address::generate(&env);
        let contributor2 = Address::generate(&env);
        
        // Initialize the contract
        // We need to mock auth for admin for the initialize call
        client.mock_auths(&[
            MockAuth {
                address: &admin,
                invoke: &MockAuthInvoke {
                    contract: &contract_id,
                    fn_name: "initialize",
                    args: vec![&env, admin.clone().into_val(&env)],
                    sub_invokes: &[],
                },
            }
        ]).initialize(&admin);


        CrowdfundingTest {
            env,
            contract_id,
            client,
            creator,
            contributor1,
            contributor2,
        }
    }
}

// Helper function to advance ledger time
fn advance_ledger_time(env: &Env, time_advance_seconds: u64) {
    let current_ledger = env.ledger().get();
    env.ledger().set(LedgerInfo {
        timestamp: current_ledger.timestamp + time_advance_seconds,
        protocol_version: current_ledger.protocol_version,
        sequence_number: current_ledger.sequence_number + 1,
        network_id: current_ledger.network_id,
        base_reserve: current_ledger.base_reserve,
        min_temp_entry_ttl: current_ledger.min_temp_entry_ttl,
        min_persistent_entry_ttl: current_ledger.min_persistent_entry_ttl,
        max_entry_ttl: current_ledger.max_entry_ttl,
    });
}

