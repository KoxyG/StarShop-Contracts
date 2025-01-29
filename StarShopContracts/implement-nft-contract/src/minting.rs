use soroban_sdk::{contractimpl, Address, Env, String, Vec};
use crate::{NFTMetadata, NFTDetail, COUNTER_KEY};
use crate::NFTContractClient;
use crate::NFTContractArgs;

#[contractimpl]
impl super::NFTContract {
    pub fn mint_nft(
        env: Env,
        to: Address,
        name: String,
        description: String,
        attributes: Vec<String>,
    ) -> u32 {
        // Verificar permisos del caller
        to.require_auth();

        // Generar nuevo ID único
        let mut current_id: u32 = env.storage().instance().get(&COUNTER_KEY).unwrap();
        current_id += 1;
        env.storage().instance().set(&COUNTER_KEY, &current_id);

        // Crear metadata y NFT
        let metadata = NFTMetadata {
            name,
            description,
            attributes,
        };

        let nft = NFTDetail {
            owner: to.clone(),
            metadata,
        };

        // Almacenar en persistent storage
        env.storage().persistent().set(&current_id, &nft);

        current_id
    }
}