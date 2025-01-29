use soroban_sdk::{symbol_short, Address, Env};
use crate::metadata::NFTDetail;

const TRANSFER_EVENT: Symbol = symbol_short!("TRANSFER");

#[derive(Clone)]
#[contracttype]
pub struct TransferEvent {
    pub from: Address,
    pub to: Address,
    pub token_id: u128,
}

#[contractimpl]
impl super::NFTContract {
    pub fn transfer_nft(env: Env, from: Address, to: Address, token_id: u128) {
        from.require_auth();

        if from == env.current_contract_address() {
            panic!("Sender cannot be contract address")
        }

        let mut nft_detail = Self::get_nft_detail(env.clone(), token_id);

        if nft_detail.owner != from {
            panic!("Not the owner of the NFT")
        }

        let transfer_event = TransferEvent { 
            from: from.clone(), 
            to: to.clone(), 
            token_id 
        };

        nft_detail.owner = to;
        env.storage().instance().set(&token_id, &nft_detail);
        env.events().publish((TRANSFER_EVENT, symbol_short!("transfer")), transfer_event);
    }

    pub fn get_nft_detail(env: Env, token_id: u128) -> NFTDetail {
        env.storage()
            .instance()
            .get(&token_id)
            .unwrap_or_else(|| panic!("NFT does not exist"))
    }

    pub fn has_nft_owner(env: Env, account: Address, token_id: u128) -> bool {
        let nft_detail = Self::get_nft_detail(env.clone(), token_id);
        nft_detail.owner == account
    }
}