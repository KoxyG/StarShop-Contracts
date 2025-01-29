use soroban_sdk::contractimpl;
use soroban_sdk::{Env, Address};
use crate::NFTContractClient;
use crate::NFTContractArgs;

#[contractimpl]
impl super::NFTContract {
    pub fn transfer_nft(env: Env, from: Address, to: Address, token_id: u32) {
        from.require_auth();

        // Verificar ownership
        let mut nft: crate::NFTDetail = env.storage().persistent().get(&token_id)
            .expect("NFT no existe");

        if nft.owner != from {
            panic!("No eres el dueño");
        }

        // Actualizar ownership
        nft.owner = to.clone();
        env.storage().persistent().set(&token_id, &nft);
    }

    pub fn burn_nft(env: Env, owner: Address, token_id: u32) {
        owner.require_auth();

        let nft: crate::NFTDetail = env.storage().persistent().get(&token_id)
            .expect("NFT no existe");

        if nft.owner != owner {
            panic!("No puedes quemar este NFT");
        }

        env.storage().persistent().remove(&token_id);
    }
}