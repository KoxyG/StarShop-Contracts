use crate::{DataKey, Error};
use soroban_sdk::{contract, contracterror, contractimpl, contracttype, Address, Env, String};

pub fn distribute(env: Env, to: Address, token_id: u64) -> Result<(), Error> {
    // Autenticar admin
    let admin = env.storage().get(&DataKey::Admin)?.ok_or(Error::Unauthorized)?;
    admin.require_auth();

    // Verificar propiedad
    let contract_address = env.current_contract_address();
    let owner = env.storage().get(&DataKey::Owner(token_id))?.ok_or(Error::NotFound)?;
    
    if owner != contract_address {
        return Err(Error::NotOwner);
    }

    // Transferir NFT
    env.storage().set(&DataKey::Owner(token_id), &to);

    Ok(())
}