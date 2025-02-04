use soroban_sdk::{
    testutils::{Address as _, AuthorizedFunction, AuthorizedInvocation},
    Address, Env, String, Vec,
};
use crate::{NFTContract, NFTDetail, NFTMetadata};

#[test]
fn test_mint_with_metadata() {
    let env = Env::default();
    let contract_id = env.register_contract(None, NFTContract);
    let client = NFTContractClient::new(&env, &contract_id);
    let user = Address::random(&env);

    // Test data
    let name = String::from_str(&env, "Test NFT");
    let description = String::from_str(&env, "A test NFT with metadata");
    let mut attributes = Vec::new(&env);
    attributes.push_back(String::from_str(&env, "attribute1"));
    attributes.push_back(String::from_str(&env, "attribute2"));

    let token_id = client.mint_nft(
        &user,
        &name,
        &description,
        &attributes,
    );

    let stored_metadata = client.get_metadata(&token_id);
    assert_eq!(stored_metadata.name, name, "Name mismatch");
    assert_eq!(stored_metadata.description, description, "Description mismatch");
    assert_eq!(stored_metadata.attributes, attributes, "Attributes mismatch");
}

#[test]
fn test_update_metadata() {
    let env = Env::default();
    let contract_id = env.register_contract(None, NFTContract);
    let client = NFTContractClient::new(&env, &contract_id);
    let admin = Address::random(&env);
    let user = Address::random(&env);

    let name = String::from_str(&env, "Initial Name");
    let description = String::from_str(&env, "Initial Description");
    let attributes = Vec::new(&env);

    let token_id = client.mint_nft(
        &user,
        &name,
        &description,
        &attributes,
    );

    let updated_name = String::from_str(&env, "Updated Name");
    let updated_description = String::from_str(&env, "Updated Description");
    let mut updated_attributes = Vec::new(&env);
    updated_attributes.push_back(String::from_str(&env, "new_attribute"));

    client.update_metadata(
        &admin,
        &token_id,
        &updated_name,
        &updated_description,
        &updated_attributes,
    );

    let stored_metadata = client.get_metadata(&token_id);
    assert_eq!(stored_metadata.name, updated_name, "Updated name mismatch");
    assert_eq!(stored_metadata.description, updated_description, "Updated description mismatch");
    assert_eq!(stored_metadata.attributes, updated_attributes, "Updated attributes mismatch");
}

#[test]
fn test_metadata_persistence_after_transfer() {
    let env = Env::default();
    let contract_id = env.register_contract(None, NFTContract);
    let client = NFTContractClient::new(&env, &contract_id);
    let original_owner = Address::random(&env);
    let new_owner = Address::random(&env);

    let name = String::from_str(&env, "Transferable NFT");
    let description = String::from_str(&env, "NFT with persistent metadata");
    let mut attributes = Vec::new(&env);
    attributes.push_back(String::from_str(&env, "transferable"));

    let token_id = client.mint_nft(
        &original_owner,
        &name,
        &description,
        &attributes,
    );

    client.transfer_nft(
        &original_owner,
        &new_owner,
        &token_id,
    );

    let stored_metadata = client.get_metadata(&token_id);
    assert_eq!(stored_metadata.name, name, "Name changed after transfer");
    assert_eq!(stored_metadata.description, description, "Description changed after transfer");
    assert_eq!(stored_metadata.attributes, attributes, "Attributes changed after transfer");
}

#[test]
#[should_panic(expected = "NFT not exist")]
fn test_metadata_removal_after_burn() {
    let env = Env::default();
    let contract_id = env.register_contract(None, NFTContract);
    let client = NFTContractClient::new(&env, &contract_id);
    let owner = Address::random(&env);

    let token_id = client.mint_nft(
        &owner,
        &String::from_str(&env, "Burnable NFT"),
        &String::from_str(&env, "NFT to be burned"),
        &Vec::new(&env),
    );

    client.burn_nft(&owner, &token_id);

    client.get_metadata(&token_id);
}

#[test]
#[should_panic(expected = "You are not the owner")]
fn test_unauthorized_metadata_update() {
    let env = Env::default();
    let contract_id = env.register_contract(None, NFTContract);
    let client = NFTContractClient::new(&env, &contract_id);
    let owner = Address::random(&env);
    let unauthorized_user = Address::random(&env);

    let token_id = client.mint_nft(
        &owner,
        &String::from_str(&env, "Protected NFT"),
        &String::from_str(&env, "NFT with protected metadata"),
        &Vec::new(&env),
    );

    client.update_metadata(
        &unauthorized_user,
        &token_id,
        &String::from_str(&env, "Unauthorized Update"),
        &String::from_str(&env, "This should fail"),
        &Vec::new(&env),
    );
}
#[cfg(test)]
use super::*;
use soroban_sdk::{testutils::Address as _, vec, Address, Env, String};

fn setup() -> (Env, Address, NFTContractClient<'static>) {
    let env = Env::default();
    let contract_id = env.register_contract(None, super::NFTContract);
    let client = NFTContractClient::new(&env, &contract_id);

    // Initialize counter within contract context
    env.as_contract(&contract_id, || {
        env.storage().instance().set(&COUNTER_KEY, &0u32);
    });

    (env, contract_id, client)
}

#[test]
fn test_mint_reward_nft() {
    let (env, contract_id, client) = setup();
    let recipient = Address::generate(&env);

    // Test minting a reward NFT
    let reward_metadata = vec![
        &env,
        String::from_str(&env, "Achievement Level: Gold"),
        String::from_str(&env, "Points: 1000"),
    ];

    // Authenticate as recipient
    env.mock_all_auths();

    let token_id = client.mint_nft(
        &recipient,
        &String::from_str(&env, "Performance Reward"),
        &String::from_str(&env, "Outstanding performance achievement reward"),
        &reward_metadata,
    );

    // Verify the minted NFT within contract context
    env.as_contract(&contract_id, || {
        let nft: NFTDetail = env.storage().persistent().get(&token_id).unwrap();
        assert_eq!(nft.owner, recipient);
        assert_eq!(
            nft.metadata.name,
            String::from_str(&env, "Performance Reward")
        );
        assert_eq!(reward_metadata.len(), nft.metadata.attributes.len());
    });
}

#[test]
fn test_mint_invoice_nft() {
    let (env, contract_id, client) = setup();
    let recipient = Address::generate(&env);

    // Test minting an invoice NFT
    let invoice_metadata = vec![
        &env,
        String::from_str(&env, "Invoice Number: INV-2024-001"),
        String::from_str(&env, "Amount: 500 USDC"),
        String::from_str(&env, "Due Date: 2025-01-31"),
    ];

    // Authenticate as recipient
    env.mock_all_auths();

    let token_id = client.mint_nft(
        &recipient,
        &String::from_str(&env, "Service Invoice"),
        &String::from_str(&env, "Professional services rendered - January 2024"),
        &invoice_metadata,
    );

    // Verify the minted NFT within contract context
    env.as_contract(&contract_id, || {
        let nft: NFTDetail = env.storage().persistent().get(&token_id).unwrap();
        assert_eq!(nft.owner, recipient);
        assert_eq!(nft.metadata.name, String::from_str(&env, "Service Invoice"));
        assert_eq!(invoice_metadata.len(), nft.metadata.attributes.len());
    });
}
