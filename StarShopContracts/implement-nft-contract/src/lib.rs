use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Address, Env, String, Symbol ,Vec};

mod minting;
mod distribution;
mod metadata;

const ADMIN_KEY: Symbol = symbol_short!("ADMIN");     // ✅ Correcto
const COUNTER_KEY: Symbol = symbol_short!("COUNTER");

#[derive(Clone, Debug, PartialEq, Eq)]
#[contracttype]
pub struct NFTMetadata {
    pub name: String,
    pub description: String,
    pub attributes: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[contracttype]
pub struct NFTDetail {
    pub owner: Address,
    pub metadata: NFTMetadata,
}

#[contract]
pub struct NFTContract;

#[contractimpl]
impl NFTContract {
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().instance().has(&ADMIN_KEY) {
            panic!("Already initialized");
        }
        env.storage().instance().set(&ADMIN_KEY, &admin);
        env.storage().instance().set(&COUNTER_KEY, &0u32);
    }

    fn check_admin(env: &Env, caller: &Address) {
        let admin: Address = env.storage().instance().get(&ADMIN_KEY).unwrap();
        if caller != &admin {
            panic!("Unauthorized");
        }
    }
}