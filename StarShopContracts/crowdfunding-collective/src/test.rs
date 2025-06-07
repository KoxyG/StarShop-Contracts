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

// Helper to create a basic product for tests
fn create_test_product<'a>(
    test: &CrowdfundingTest<'a>, 
    funding_goal: u64, 
    deadline_offset_seconds: u64,
    reward_tiers_override: Option<Vec<RewardTier>>,
    milestones_override: Option<Vec<Milestone>>,
) -> u32 {
    let env = &test.env;
    let name = String::from_str(env, "Test Product");
    let description = String::from_str(env, "A great product for testing");
    let deadline = env.ledger().timestamp() + deadline_offset_seconds;

    let reward_tiers = reward_tiers_override.unwrap_or_else(|| vec![
        env,
        RewardTier {
            id: 1,
            min_contribution: 50,
            description: String::from_str(env, "Basic Reward"),
            discount: 5,
        },
    ]);
    let milestones = milestones_override.unwrap_or_else(|| vec![
        env,
        Milestone {
            id: 0, // Milestones Vec is 0-indexed
            description: String::from_str(env, "Phase 1"),
            target_date: deadline + 100, // After product deadline
            completed: false,
        },
    ]);

    test.client
        .mock_auths(&[
            MockAuth {
                address: &test.creator,
                invoke: &MockAuthInvoke {
                    contract: &test.contract_id,
                    fn_name: "create_product",
                    args: vec![
                        env,
                        test.creator.clone().into_val(env),
                        name.clone().into_val(env),
                        description.clone().into_val(env),
                        funding_goal.into_val(env),
                        deadline.into_val(env),
                        reward_tiers.clone().into_val(env),
                        milestones.clone().into_val(env),
                    ],
                    sub_invokes: &[],
                },
            }
        ])
        .create_product(
            &test.creator,
            &name,
            &description,
            &funding_goal,
            &deadline,
            &reward_tiers,
            &milestones,
        )
}


#[test]
fn test_initialization_and_admin_set() {
    // Setup implicitly calls initialize.
    // If we had a get_admin or get_next_product_id, we'd assert here.
    // For now, successful setup implies initialize worked.
    // We can test next_product_id indirectly.
    let test = CrowdfundingTest::setup();
    let product_id = create_test_product(&test, 1000, 10000, None, None);
    assert_eq!(product_id, 1, "First product ID should be 1 after initialization");

    let product_id_2 = create_test_product(&test, 1000, 10000, None, None);
    assert_eq!(product_id_2, 2, "Second product ID should be 2");
}

#[test]
#[should_panic(expected = "HostError: Error(Auth, InvalidAction)")]
fn test_initialize_unauthorized_attempt() {
    let env = Env::default();
    // DO NOT mock_all_auths here
    let contract_id = env.register(CrowdfundingCollective, ());
    let client = CrowdfundingCollectiveClient::new(&env, &contract_id);
    let real_admin_for_arg = Address::generate(&env);

    // Attempt to initialize where admin_wannabe is the invoker but not the 'admin' argument's authorizer
    // The panic comes from real_admin_for_arg.require_auth()
    client.initialize(&real_admin_for_arg);
}

#[test]
fn test_create_product_successful() {
    let test = CrowdfundingTest::setup();
    let env = &test.env;
    let funding_goal = 10000;
    let deadline_offset = 3600; // 1 hour
    let product_id = create_test_product(&test, funding_goal, deadline_offset, None, None);

    let product_data = test.client.get_product(&product_id);
    assert_eq!(product_data.id, product_id);
    assert_eq!(product_data.creator, test.creator);
    assert_eq!(product_data.name, String::from_str(env, "Test Product"));
    assert_eq!(product_data.funding_goal, funding_goal);
    assert_eq!(product_data.deadline, env.ledger().timestamp() + deadline_offset); // Timestamp taken at product creation
    assert_eq!(product_data.status, ProductStatus::Active);
    assert_eq!(product_data.total_funded, 0);

    let rewards = test.client.get_reward_tiers(&product_id);
    assert_eq!(rewards.len(), 1);
    assert_eq!(rewards.get(0).unwrap().id, 1);

    let milestones = test.client.get_milestones(&product_id);
    assert_eq!(milestones.len(), 1);
    assert_eq!(milestones.get(0).unwrap().description, String::from_str(env, "Phase 1"));

    let contributions = test.client.get_contributions(&product_id);
    assert_eq!(contributions.len(), 0);
}

#[test]
#[should_panic(expected = "Funding goal must be greater than zero")]
fn test_create_product_zero_funding_goal() {
    let test = CrowdfundingTest::setup();
    create_test_product(&test, 0, 3600, None, None);
}

#[test]
#[should_panic(expected = "Deadline must be in the future")]
fn test_create_product_past_deadline() {
    let test = CrowdfundingTest::setup();
    let env = &test.env;
    env.ledger().set_timestamp(100);

    let name = String::from_str(env, "Past Deadline");
    let description = String::from_str(env, "This product has a past deadline");
    let funding_goal = 1000;
    let deadline = 50; // Past deadline, should be less than env.ledger().timestamp()
    let reward_tiers = vec![env, RewardTier {
        id: 1,
        min_contribution: 50,
        description: String::from_str(env, "Basic Reward"),
        discount: 5,
    }];
    let milestones = vec![env, Milestone {
        id: 0,
        description: String::from_str(env, "Phase 1"),
        target_date: env.ledger().timestamp() + 100, // After product deadline
        completed: false,
    }];

    // create_test_product uses env.ledger().timestamp() + offset, so we need to call client directly
     test.client
     .mock_auths(&[
        MockAuth {
            address: &test.creator,
            invoke: &MockAuthInvoke {
                contract: &test.contract_id,
                fn_name: "create_product",
                args: vec![
                    env,
                    test.creator.clone().into_val(env),
                    name.clone().into_val(env),
                    description.clone().into_val(env),
                    funding_goal.into_val(env),
                    deadline.into_val(env),
                    reward_tiers.clone().into_val(env),
                    milestones.clone().into_val(env),
                ],
                sub_invokes: &[],
            },
        }
    ])
        .create_product(
            &test.creator,
            &name,
            &description,
            &funding_goal,
            &deadline, // This is 50, which is past the current ledger timestamp of 100
            &reward_tiers,
            &milestones,
        );
}

#[test]
fn test_contribute_successful_and_fund_product() {
    let test = CrowdfundingTest::setup();
    let env = &test.env;
    let funding_goal = 1000;
    let product_id = create_test_product(&test, funding_goal, 3600, None, None);
    
    let contribution1_amount = 600;
    test.client
        .mock_auths(&[MockAuth { address: &test.contributor1, invoke: &MockAuthInvoke { contract: &test.contract_id, fn_name: "contribute", args: vec![env, test.contributor1.clone().into_val(env), product_id.into_val(env), contribution1_amount.into_val(env)], sub_invokes: &[] } }])
        .contribute(&test.contributor1, &product_id, &contribution1_amount);

    let product_data = test.client.get_product(&product_id);
    assert_eq!(product_data.total_funded, contribution1_amount);
    assert_eq!(product_data.status, ProductStatus::Active);

    let contributions = test.client.get_contributions(&product_id);
    assert_eq!(contributions.len(), 1);
    assert_eq!(contributions.get(0).unwrap().contributor, test.contributor1);
    assert_eq!(contributions.get(0).unwrap().amount, contribution1_amount);

    // Second contribution to meet the goal
    let contribution2_amount = funding_goal - contribution1_amount; // 400
    test.client
        .mock_auths(&[MockAuth { address: &test.contributor2, invoke: &MockAuthInvoke { contract: &test.contract_id, fn_name: "contribute", args: vec![env, test.contributor2.clone().into_val(env), product_id.into_val(env), contribution2_amount.into_val(env)], sub_invokes: &[] } }])
        .contribute(&test.contributor2, &product_id, &contribution2_amount);

    let product_data_funded = test.client.get_product(&product_id);
    assert_eq!(product_data_funded.total_funded, funding_goal);
    assert_eq!(product_data_funded.status, ProductStatus::Funded);
}

#[test]
#[should_panic(expected = "Product is not active")]
fn test_contribute_to_funded_product_fails() {
    let test = CrowdfundingTest::setup();
    let funding_goal = 1000;

    let contribution1_amount = 1000;

    let product_id = create_test_product(&test, funding_goal, 3600, None, None);
    test.client
        .mock_auths(&[MockAuth { address: &test.contributor1, invoke: &MockAuthInvoke { contract: &test.contract_id, fn_name: "contribute", args: vec![&test.env, test.contributor1.clone().into_val(&test.env), product_id.into_val(&test.env), contribution1_amount.into_val(&test.env)], sub_invokes: &[] } }])
        .contribute(&test.contributor1, &product_id, &contribution1_amount); // Fund it
    assert_eq!(test.client.get_product(&product_id).status, ProductStatus::Funded);

    let contribution2_amount = 100; // Trying to contribute again after funding
    test.client
        .mock_auths(&[MockAuth { address: &test.contributor2, invoke: &MockAuthInvoke { contract: &test.contract_id, fn_name: "contribute", args: vec![&test.env, test.contributor2.clone().into_val(&test.env), product_id.into_val(&test.env), contribution2_amount.into_val(&test.env)], sub_invokes: &[] } }])
        .contribute(&test.contributor2, &product_id, &contribution2_amount); // Should panic
}

#[test]
#[should_panic(expected = "Funding period has ended")]
fn test_contribute_after_deadline_fails() {
    let test = CrowdfundingTest::setup();
    let funding_goal = 1000;
    let contribution1_amount = 1000;
    let product_id = create_test_product(&test, funding_goal, 100, None, None); // Short deadline: 100s
    advance_ledger_time(&test.env, 101); // Pass deadline
    test.client
        .mock_auths(&[MockAuth { address: &test.contributor1, invoke: &MockAuthInvoke { contract: &test.contract_id, fn_name: "contribute", args: vec![&test.env, test.contributor1.clone().into_val(&test.env), product_id.into_val(&test.env), contribution1_amount.into_val(&test.env)], sub_invokes: &[] } }])
        .contribute(&test.contributor1, &product_id, &contribution1_amount); // Should panic
}

#[test]
#[should_panic(expected = "Contribution must be greater than zero")]
fn test_contribute_zero_amount_fails() {
    let test = CrowdfundingTest::setup();
    let funding_goal = 1000;
    let product_id = create_test_product(&test, funding_goal, 3600, None, None);
    let contribution1_amount = 0; // Zero contribution amount
    test.client
        .mock_auths(&[MockAuth { address: &test.contributor1, invoke: &MockAuthInvoke { contract: &test.contract_id, fn_name: "contribute", args: vec![&test.env, test.contributor1.clone().into_val(&test.env), product_id.into_val(&test.env), contribution1_amount.into_val(&test.env)], sub_invokes: &[] } }])
        .contribute(&test.contributor1, &product_id, &contribution1_amount); // Should panic
}

#[test]
#[should_panic(expected = "Contribution would exceed funding goal")]
fn test_contribute_exceeds_goal_fails() {
    let test = CrowdfundingTest::setup();
    let product_id = create_test_product(&test, 100, 3600, None, None);
    let contribution1_amount = 150; // Exceeds funding goal of 100
    test.client
        .mock_auths(&[MockAuth { address: &test.contributor1, invoke: &MockAuthInvoke { contract: &test.contract_id, fn_name: "contribute", args: vec![&test.env, test.contributor1.clone().into_val(&test.env), product_id.into_val(&test.env), contribution1_amount.into_val(&test.env)], sub_invokes: &[] } }])
        .contribute(&test.contributor1, &product_id, &contribution1_amount); // Contribute 150
}

#[test]
fn test_update_milestone_successful() {
    let test = CrowdfundingTest::setup();
    let env = &test.env;
    let product_id = create_test_product(&test, 100, 3600, None, None);
    let contribution1_amount = 100;
    test.client
        .mock_auths(&[MockAuth { address: &test.contributor1, invoke: &MockAuthInvoke { contract: &test.contract_id, fn_name: "contribute", args: vec![env, test.contributor1.clone().into_val(env), product_id.into_val(env), contribution1_amount.into_val(env)], sub_invokes: &[] } }])
        .contribute(&test.contributor1, &product_id, &contribution1_amount); // Fund
    assert_eq!(test.client.get_product(&product_id).status, ProductStatus::Funded);

    let milestone_id_to_update = 0; // First milestone
    test.client
        .mock_auths(&[MockAuth { address: &test.creator, invoke: &MockAuthInvoke { contract: &test.contract_id, fn_name: "update_milestone", args: vec![env, test.creator.clone().into_val(env), product_id.into_val(env), milestone_id_to_update.into_val(env)], sub_invokes: &[] } }])
        .update_milestone(&test.creator, &product_id, &milestone_id_to_update);

    let milestones = test.client.get_milestones(&product_id);
    assert!(milestones.get(milestone_id_to_update).unwrap().completed);
}

#[test]
#[should_panic(expected = "Only the creator can update milestones")]
fn test_update_milestone_unauthorized_user_fails() {
    let test = CrowdfundingTest::setup();
    let product_id = create_test_product(&test, 100, 3600, None, None);
    let contributor1_amount = 100;
    test.client
        .mock_auths(&[MockAuth { address: &test.contributor1, invoke: &MockAuthInvoke { contract: &test.contract_id, fn_name: "contribute", args: vec![&test.env, test.contributor1.clone().into_val(&test.env), product_id.into_val(&test.env), contributor1_amount.into_val(&test.env)], sub_invokes: &[] } }])
        .contribute(&test.contributor1, &product_id, &contributor1_amount); // Fund
    
    let non_creator = Address::generate(&test.env);
    let milestone_id = 0; // First milestone
    // non_creator tries to update, should fail due to product.creator != creator check
    test.client
        .mock_auths(&[MockAuth { address: &non_creator, invoke: &MockAuthInvoke { contract: &test.contract_id, fn_name: "update_milestone", args: vec![&test.env, non_creator.into_val(&test.env), product_id.into_val(&test.env), milestone_id.into_val(&test.env)], sub_invokes: &[] } }])
        .update_milestone(&non_creator, &product_id, &milestone_id);
}

#[test]
#[should_panic(expected = "Product is not funded")]
fn test_update_milestone_product_not_funded_fails() {
    let test = CrowdfundingTest::setup();
    let product_id = create_test_product(&test, 100, 3600, None, None); // Not funded
    let milestone_id = 0;
    test.client
        .mock_auths(&[MockAuth { address: &test.creator, invoke: &MockAuthInvoke { contract: &test.contract_id, fn_name: "update_milestone", args: vec![&test.env, test.creator.clone().into_val(&test.env), product_id.into_val(&test.env), milestone_id.into_val(&test.env)], sub_invokes: &[] } }])
        .update_milestone(&test.creator, &product_id, &milestone_id); // Should panic
}
