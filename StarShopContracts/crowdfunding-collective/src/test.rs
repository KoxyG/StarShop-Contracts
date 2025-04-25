#![cfg(test)]

use crate::types::*;
use crate::{CrowdfundingCollective, CrowdfundingCollectiveClient};
use soroban_sdk::{
    Address, Env, String, Vec,
    testutils::{Address as _, Ledger},
};

#[test]
fn test_initialize_contract() {
    let env = Env::default();
    let admin = Address::generate(&env);

    let contract_address = env.register(CrowdfundingCollective, ());
    let contract_client = CrowdfundingCollectiveClient::new(&env, &contract_address);

    env.mock_all_auths();
    contract_client.initialize(&admin);

    assert!(true, "Initialize function completed without errors");
}

#[test]
fn test_create_product() {
    let env = Env::default();
    let creator = Address::generate(&env);

    let contract_address = env.register(CrowdfundingCollective, ());
    let contract_client = CrowdfundingCollectiveClient::new(&env, &contract_address);

    env.mock_all_auths();
    let admin = Address::generate(&env);
    contract_client.initialize(&admin);

    let mut reward_tiers = Vec::new(&env);
    reward_tiers.push_back(RewardTier {
        id: 0,
        min_contribution: 10000000,
        description: String::from_str(&env, "10% discount"),
        discount: 10,
    });

    let mut milestones = Vec::new(&env);
    milestones.push_back(Milestone {
        id: 0,
        description: String::from_str(&env, "Prototype complete"),
        target_date: env.ledger().timestamp() + 86400,
        completed: false,
    });

    let product_id = contract_client.create_product(
        &creator,
        &String::from_str(&env, "New Gadget"),
        &String::from_str(&env, "Innovative device"),
        &100000000,
        &(env.ledger().timestamp() + 86400),
        &reward_tiers,
        &milestones,
    );

    let product = contract_client.get_product(&product_id);
    assert_eq!(product.id, product_id);
    assert_eq!(product.creator, creator);
    assert_eq!(product.funding_goal, 100000000);
    assert_eq!(product.status, ProductStatus::Active);

    let stored_tiers = contract_client.get_reward_tiers(&product_id);
    assert_eq!(stored_tiers.len(), 1);
    assert_eq!(stored_tiers.get(0).unwrap().min_contribution, 10000000);

    let stored_milestones = contract_client.get_milestones(&product_id);
    assert_eq!(stored_milestones.len(), 1);
    assert_eq!(
        stored_milestones.get(0).unwrap().description,
        String::from_str(&env, "Prototype complete")
    );
}

#[test]
fn test_contribute() {
    let env = Env::default();
    let creator = Address::generate(&env);
    let contributor = Address::generate(&env);

    let contract_address = env.register(CrowdfundingCollective, ());
    let contract_client = CrowdfundingCollectiveClient::new(&env, &contract_address);

    env.mock_all_auths();
    let admin = Address::generate(&env);
    contract_client.initialize(&admin);

    let product_id = contract_client.create_product(
        &creator,
        &String::from_str(&env, "New Gadget"),
        &String::from_str(&env, "Innovative device"),
        &100000000,
        &(env.ledger().timestamp() + 86400),
        &Vec::new(&env),
        &Vec::new(&env),
    );

    let contribution_amount = 50000000;
    contract_client.contribute(&contributor, &product_id, &contribution_amount);

    let contributions = contract_client.get_contributions(&product_id);
    assert_eq!(contributions.len(), 1);
    assert_eq!(contributions.get(0).unwrap().contributor, contributor);
    assert_eq!(contributions.get(0).unwrap().amount, contribution_amount);

    let product = contract_client.get_product(&product_id);
    assert_eq!(product.total_funded, contribution_amount);
}

#[test]
fn test_contribute_exceeds_max_limit() {
    let env = Env::default();
    let creator = Address::generate(&env);
    let contributor = Address::generate(&env);

    let contract_address = env.register(CrowdfundingCollective, ());
    let contract_client = CrowdfundingCollectiveClient::new(&env, &contract_address);

    env.mock_all_auths();
    let admin = Address::generate(&env);
    contract_client.initialize(&admin);

    let product_id = contract_client.create_product(
        &creator,
        &String::from_str(&env, "New Gadget"),
        &String::from_str(&env, "Innovative device"),
        &100000000,
        &(env.ledger().timestamp() + 86400),
        &Vec::new(&env),
        &Vec::new(&env),
    );

    let result = contract_client.try_contribute(&contributor, &product_id, &200000000);
    assert!(
        result.is_err(),
        "Contribution should fail due to exceeding funding goal"
    );
}

#[test]
fn test_funding_goal_met() {
    let env = Env::default();
    let creator = Address::generate(&env);
    let contributor = Address::generate(&env);

    let contract_address = env.register(CrowdfundingCollective, ());
    let contract_client = CrowdfundingCollectiveClient::new(&env, &contract_address);

    env.mock_all_auths();
    let admin = Address::generate(&env);
    contract_client.initialize(&admin);

    let product_id = contract_client.create_product(
        &creator,
        &String::from_str(&env, "New Gadget"),
        &String::from_str(&env, "Innovative device"),
        &100000000,
        &(env.ledger().timestamp() + 86400),
        &Vec::new(&env),
        &Vec::new(&env),
    );

    contract_client.contribute(&contributor, &product_id, &100000000);

    let product = contract_client.get_product(&product_id);
    assert_eq!(product.status, ProductStatus::Funded);
    assert_eq!(product.total_funded, 100000000);
}

#[test]
fn test_update_milestone() {
    let env = Env::default();
    let creator = Address::generate(&env);
    let contributor = Address::generate(&env);

    let contract_address = env.register(CrowdfundingCollective, ());
    let contract_client = CrowdfundingCollectiveClient::new(&env, &contract_address);

    env.mock_all_auths();
    let admin = Address::generate(&env);
    contract_client.initialize(&admin);

    let mut milestones = Vec::new(&env);
    milestones.push_back(Milestone {
        id: 0,
        description: String::from_str(&env, "Prototype complete"),
        target_date: env.ledger().timestamp() + 86400,
        completed: false,
    });
    let product_id = contract_client.create_product(
        &creator,
        &String::from_str(&env, "New Gadget"),
        &String::from_str(&env, "Innovative device"),
        &100000000,
        &(env.ledger().timestamp() + 86400),
        &Vec::new(&env),
        &milestones,
    );

    contract_client.contribute(&contributor, &product_id, &100000000);
    contract_client.update_milestone(&creator, &product_id, &0);

    let milestones = contract_client.get_milestones(&product_id);
    assert!(milestones.get(0).unwrap().completed);
}

#[test]
fn test_distribute_funds() {
    let env = Env::default();
    let creator = Address::generate(&env);
    let contributor = Address::generate(&env);

    let contract_address = env.register(CrowdfundingCollective, ());
    let contract_client = CrowdfundingCollectiveClient::new(&env, &contract_address);

    env.mock_all_auths();
    let admin = Address::generate(&env);
    contract_client.initialize(&admin);

    let mut milestones = Vec::new(&env);
    milestones.push_back(Milestone {
        id: 0,
        description: String::from_str(&env, "Prototype complete"),
        target_date: env.ledger().timestamp() + 86400,
        completed: false,
    });
    let product_id = contract_client.create_product(
        &creator,
        &String::from_str(&env, "New Gadget"),
        &String::from_str(&env, "Innovative device"),
        &100000000,
        &(env.ledger().timestamp() + 86400),
        &Vec::new(&env),
        &milestones,
    );

    contract_client.contribute(&contributor, &product_id, &100000000);
    contract_client.update_milestone(&creator, &product_id, &0);
    contract_client.distribute_funds(&product_id);

    let product = contract_client.get_product(&product_id);
    assert_eq!(product.status, ProductStatus::Completed);
}

#[test]
fn test_refund_contributors() {
    let env = Env::default();
    let creator = Address::generate(&env);
    let contributor = Address::generate(&env);

    let contract_address = env.register(CrowdfundingCollective, ());
    let contract_client = CrowdfundingCollectiveClient::new(&env, &contract_address);

    env.mock_all_auths();
    let admin = Address::generate(&env);
    contract_client.initialize(&admin);

    let product_id = contract_client.create_product(
        &creator,
        &String::from_str(&env, "New Gadget"),
        &String::from_str(&env, "Innovative device"),
        &100000000,
        &(env.ledger().timestamp() + 86400),
        &Vec::new(&env),
        &Vec::new(&env),
    );

    let contribution_amount = 50000000;
    contract_client.contribute(&contributor, &product_id, &contribution_amount);

    env.ledger().with_mut(|ledger| {
        ledger.timestamp += 86401;
    });

    contract_client.refund_contributors(&product_id);

    let product = contract_client.get_product(&product_id);
    assert_eq!(product.status, ProductStatus::Failed);

    let contributions = contract_client.get_contributions(&product_id);
    assert_eq!(contributions.len(), 0);

    let total_funded = env.as_contract(&contract_address, || {
        env.storage()
            .instance()
            .get(&DataKey::ContributionsTotal(product_id))
            .unwrap_or(0u64)
    });
    assert_eq!(total_funded, 0);
}

#[test]
fn test_unauthorized_milestone_update() {
    let env = Env::default();
    let creator = Address::generate(&env);
    let unauthorized = Address::generate(&env);

    let contract_address = env.register(CrowdfundingCollective, ());
    let contract_client = CrowdfundingCollectiveClient::new(&env, &contract_address);

    env.mock_all_auths();
    let admin = Address::generate(&env);
    contract_client.initialize(&admin);

    let mut milestones = Vec::new(&env);
    milestones.push_back(Milestone {
        id: 0,
        description: String::from_str(&env, "Prototype complete"),
        target_date: env.ledger().timestamp() + 86400,
        completed: false,
    });
    let product_id = contract_client.create_product(
        &creator,
        &String::from_str(&env, "New Gadget"),
        &String::from_str(&env, "Innovative device"),
        &100000000,
        &(env.ledger().timestamp() + 86400),
        &Vec::new(&env),
        &milestones,
    );

    let result = contract_client.try_update_milestone(&unauthorized, &product_id, &0);
    assert!(result.is_err(), "Unauthorized milestone update should fail");
}
