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
