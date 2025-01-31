use crate::NFTContractArgs;
use crate::NFTContractClient;
use soroban_sdk::contractimpl;
use soroban_sdk::{Address, Env, String, Vec};

#[contractimpl]
impl super::NFTContract {
    pub fn update_metadata(
        env: Env,
        admin: Address,
        token_id: u32,
        name: String,
        description: String,
        attributes: Vec<String>,
    ) {
        Self::check_admin(&env, &admin);

        let mut nft: crate::NFTDetail = env
            .storage()
            .persistent()
            .get(&token_id)
            .expect("NFT not exist");

        nft.metadata = crate::NFTMetadata {
            name,
            description,
            attributes,
        };

        env.storage().persistent().set(&token_id, &nft);
    }

    pub fn get_metadata(env: Env, token_id: u32) -> crate::NFTMetadata {
        let nft: crate::NFTDetail = env
            .storage()
            .persistent()
            .get(&token_id)
            .expect("NFT not exist");
        nft.metadata
    }
}
