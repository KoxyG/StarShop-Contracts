// metadata.rs
use soroban_sdk::{Env, Address};
use crate::{DataKey, Metadata, Error};

pub fn attach(env: &Env, token_id: u64, metadata: Metadata) -> Result<(), Error> {
    env.storage().set(&DataKey::Metadata(token_id), &metadata);
    Ok(())
}

pub fn get(env: &Env, token_id: u64) -> Result<Metadata, Error> {
    env.storage()
        .get(&DataKey::Metadata(token_id))?
        .ok_or(Error::NotFound)
}