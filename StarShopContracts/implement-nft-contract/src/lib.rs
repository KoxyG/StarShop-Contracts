use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short, Symbol, Address, Env, String,
};

mod minting;
mod distribution;
mod metadata;

pub use minting::*;
pub use distribution::*;
pub use metadata::*;

const METADATA_KEY: Symbol = symbol_short!("METADATA");
const COUNTER: Symbol = symbol_short!("COUNTER");

#[derive(Clone)]
#[contracttype]
pub struct NFTMetadata {
    pub name: String,
    pub symbol: String,
}

#[derive(Clone)]
#[contracttype]
pub enum DataKey {
    Admin,
}

#[contract]
pub struct NFTContract;

#[contractimpl]
impl NFTContract {
    pub fn initialize(env: Env, admin: Address, name: String, symbol: String) {
        if has_administrator(env.clone()) {
            panic!("Contract already initialized")
        }

        let metadata = NFTMetadata { name, symbol };
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().persistent().set(&METADATA_KEY, &metadata);
    }

    // Helper functions
    pub fn read_administrator(env: Env) -> Address {
        env.storage().instance().get(&DataKey::Admin).unwrap()
    }

    pub fn name(env: Env) -> String {
        let metadata: NFTMetadata = env.storage().persistent().get(&METADATA_KEY).unwrap();
        metadata.name
    }

    pub fn symbol(env: Env) -> String {
        let metadata: NFTMetadata = env.storage().persistent().get(&METADATA_KEY).unwrap();
        metadata.symbol
    }
}

pub fn has_administrator(env: Env) -> bool {
    let key = DataKey::Admin;
    env.storage().instance().has(&key)
}

#[cfg(test)]
mod test;