use soroban_sdk::{symbol_short, Address, Env, String};
use crate::metadata::NFTDetail;

const MINT_EVENT: Symbol = symbol_short!("MINT");
const BURN_EVENT: Symbol = symbol_short!("BURN");
const COUNTER: Symbol = symbol_short!("COUNTER");

#[derive(Clone)]
#[contracttype]
pub struct MintEvent {
    pub address: Address,
    pub token_id: u128,
}

#[derive(Clone)]
#[contracttype]
pub struct BurnEvent {
    pub address: Address,
    pub token_id: u128,
}

#[contractimpl]
impl super::NFTContract {
    pub fn mint_nft(env: Env, to: Address, token_uri: String) -> u128 {
        to.require_auth();

        if to == env.current_contract_address() {
            panic!("Sender cannot be contract address")
        } else if token_uri.is_empty() {
            panic!("NFT URI cannot be empty")
        }

        let mut token_id: u128 = env.storage().instance().get(&COUNTER).unwrap_or(0);
        token_id += 1;

        let mint_event = MintEvent { 
            address: to.clone(), 
            token_id 
        };
        
        let nft_detail = NFTDetail {
            owner: to,
            uri: token_uri,
            metadata: None, // Will be set later via metadata module
        };

        env.storage().instance().set(&token_id, &nft_detail);
        env.storage().instance().set(&COUNTER, &token_id);
        env.events().publish((MINT_EVENT, symbol_short!("mint")), mint_event);
        
        token_id
    }

    pub fn burn_nft(env: Env, owner: Address, token_id: u128) {
        owner.require_auth();

        let nft_detail = Self::get_nft_detail(env.clone(), token_id);

        if nft_detail.owner != owner {
            panic!("Not the owner of the NFT");
        }

        if owner == env.current_contract_address() {
            panic!("Sender cannot be contract address");
        }

        let burn_event = BurnEvent { 
            address: owner.clone(), 
            token_id 
        };

        env.storage().instance().remove(&token_id);
        env.events().publish((BURN_EVENT, symbol_short!("burn")), burn_event);
    }
}