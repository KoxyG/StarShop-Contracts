use crate::NFTContractArgs;
use crate::NFTContractClient;
use crate::{NFTDetail, NFTMetadata, COUNTER_KEY};
use soroban_sdk::{contractimpl, Address, Env, String, Vec};

#[contractimpl]
impl super::NFTContract {
    pub fn mint_nft(
        env: Env,
        to: Address,
        name: String,
        description: String,
        attributes: Vec<String>,
    ) -> u32 {
        to.require_auth();

        let current_id: u32 = env.storage().instance().get(&COUNTER_KEY).unwrap();
        
        // SECURITY FIX: Prevent integer overflow in token counter
        // Check for overflow before incrementing to prevent wrapping to 0
        let next_id = current_id.checked_add(1)
            .expect("Token counter overflow: Maximum number of tokens (4,294,967,295) reached");
        
        env.storage().instance().set(&COUNTER_KEY, &next_id);

        let metadata = NFTMetadata {
            name,
            description,
            attributes,
        };

        let nft = NFTDetail {
            owner: to.clone(),
            metadata,
        };

        env.storage().persistent().set(&next_id, &nft);

        next_id
    }
}
