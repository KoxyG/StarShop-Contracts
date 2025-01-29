use soroban_sdk::{Address, Env, String};
use std::collections::HashMap;

#[derive(Clone)]
#[contracttype]
pub struct NFTMetadataDetails {
    pub description: String,
    pub attributes: HashMap<String, String>,
}

#[derive(Clone)]
#[contracttype]
pub struct NFTDetail {
    pub owner: Address,
    pub uri: String,
    pub metadata: Option<NFTMetadataDetails>,
}

#[contractimpl]
impl super::NFTContract {
    pub fn set_nft_metadata(
        env: Env,
        token_id: u128,
        description: String,
        attributes: HashMap<String, String>,
    ) {
        let admin = Self::read_administrator(env.clone());
        admin.require_auth();

        let mut nft_detail = Self::get_nft_detail(env.clone(), token_id);
        
        let metadata = NFTMetadataDetails {
            description,
            attributes,
        };

        nft_detail.metadata = Some(metadata);
        env.storage().instance().set(&token_id, &nft_detail);
    }

    pub fn get_nft_metadata(env: Env, token_id: u128) -> Option<NFTMetadataDetails> {
        let nft_detail = Self::get_nft_detail(env, token_id);
        nft_detail.metadata
    }
}