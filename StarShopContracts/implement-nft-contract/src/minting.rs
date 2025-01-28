use soroban_sdk::{Env, Address};  // Añadimos import de Env
use crate::{DataKey, Error, Metadata};
use crate::metadata;  // Importamos el módulo metadata

pub fn mint(env: Env, metadata: Metadata) -> Result<(), Error> {
    // Verificar que el llamante es el admin
    let admin = env.storage().get(&DataKey::Admin)?.ok_or(Error::Unauthorized)?;
    admin.require_auth();

    // Generar nuevo ID único
    let next_id: u64 = env.storage().get(&DataKey::NextId)?.unwrap_or(0);
    env.storage().set(&DataKey::NextId, &(next_id + 1));

    // Asignar propietario inicial (el contrato mismo)
    let contract_address = env.current_contract_address();
    env.storage().set(&DataKey::Owner(next_id), &contract_address);

    // Guardar metadatos
    metadata::attach(env, next_id, metadata)?;

    Ok(())
}