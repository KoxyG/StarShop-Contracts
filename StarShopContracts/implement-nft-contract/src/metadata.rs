use soroban_sdk::contractimpl;
use soroban_sdk::{Env, Address, String, Vec};
use crate::NFTContractClient;
use crate::NFTContractArgs;

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
        // Solo el admin puede actualizar metadata
        Self::check_admin(&env, &admin);

        let mut nft: crate::NFTDetail = env.storage().persistent().get(&token_id)
            .expect("NFT no existe");

        nft.metadata = crate::NFTMetadata {
            name,
            description,
            attributes,
        };

        env.storage().persistent().set(&token_id, &nft);
    }

    pub fn get_metadata(env: Env, token_id: u32) -> crate::NFTMetadata {
        let nft: crate::NFTDetail = env.storage().persistent().get(&token_id)
            .expect("NFT no existe");
        nft.metadata
    }
}