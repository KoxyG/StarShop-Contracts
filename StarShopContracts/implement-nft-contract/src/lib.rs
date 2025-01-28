#![no_std]
use soroban_sdk::{contract, contracterror, contractimpl, contracttype, Address, Env, String};

mod minting;
mod distribution;
mod metadata;

#[contract]
pub struct Contract;

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Metadata {
    pub purchase_details: String,
    pub reward_reason: String,
}

#[contracttype]
#[derive(Clone)]
enum DataKey {
    Admin,        // Almacena la dirección del admin
    NextId,       // Contador para IDs de NFTs
    Owner(u64),   // Dueño de cada NFT por ID
    Metadata(u64), // Metadatos asociados a cada NFT
}

#[contracterror]
#[repr(u32)]
pub enum Error {
    Unauthorized = 1,
    NotOwner = 2,
    NotFound = 3,
}

#[contractimpl]
impl Contract {
    // Función de inicialización (ya existente)
    pub fn initialize(env: Env, admin: Address) {
        env.storage().set(&DataKey::Admin, &admin);
        env.storage().set(&DataKey::NextId, &0);
    }
    
    // Función de Minting (conecta con minting.rs)
    pub fn mint(env: Env, metadata: Metadata) -> Result<(), Error> {
        // Verifica que solo el admin pueda mintear
        let admin = env.storage().get(&DataKey::Admin)?.ok_or(Error::Unauthorized)?;
        admin.require_auth();
        
        minting::mint(env, metadata)
    }
    
    // Función de Distribución (conecta con distribution.rs)
    pub fn distribute(env: Env, to: Address, token_id: u64) -> Result<(), Error> {
        // Solo el admin puede distribuir
        let admin = env.storage().get(&DataKey::Admin)?.ok_or(Error::Unauthorized)?;
        admin.require_auth();
        
        distribution::distribute(env, to, token_id)
    }
    
    // Obtener metadatos (conecta con metadata.rs)
    pub fn get_metadata(env: Env, token_id: u64) -> Result<Metadata, Error> {
        metadata::get(env, token_id)
    }
    
    // Obtener dueño de un NFT
    pub fn get_owner(env: Env, token_id: u64) -> Result<Address, Error> {
        env.storage()
            .get(&DataKey::Owner(token_id))?
            .ok_or(Error::NotFound)
    }
    
    // Obtener próximo ID disponible (útil para frontend)
    pub fn next_id(env: Env) -> Result<u64, Error> {
        Ok(env.storage().get(&DataKey::NextId)?.unwrap_or(0))
    }
}