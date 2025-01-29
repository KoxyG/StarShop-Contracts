use soroban_sdk::contractimpl;
use soroban_sdk::{Env, Address};
use crate::NFTContractClient;
use crate::NFTContractArgs;

#[contractimpl]
impl super::NFTContract {
    pub fn transfer_nft(env: Env, from: Address, to: Address, token_id: u32) {
        from.require_auth();

        let mut nft: crate::NFTDetail = env.storage().persistent().get(&token_id)
            .expect("NFT not exist");

        if nft.owner != from {
            panic!("You are not the owner");
        }

        nft.owner = to.clone();
        env.storage().persistent().set(&token_id, &nft);
    }

    pub fn burn_nft(env: Env, owner: Address, token_id: u32) {
        owner.require_auth();

        let nft: crate::NFTDetail = env.storage().persistent().get(&token_id)
            .expect("NFT not exist");

        if nft.owner != owner {
            panic!("You can't burn this NFT");
        }

        env.storage().persistent().remove(&token_id);
    }
}