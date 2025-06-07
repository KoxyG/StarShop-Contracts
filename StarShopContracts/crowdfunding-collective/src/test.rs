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
