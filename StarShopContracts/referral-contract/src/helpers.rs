use crate::admin::AdminModule;
use crate::types::{DataKey, Error, UserData, VerificationStatus};
use soroban_sdk::{Address, Env};

pub fn get_user_data(env: &Env, user: &Address) -> Result<UserData, Error> {
    env.storage()
        .persistent()
        .get(&DataKey::User(user.clone()))
        .ok_or(Error::UserNotFound)
}

pub fn user_exists(env: &Env, user: &Address) -> bool {
    env.storage().persistent().has(&DataKey::User(user.clone()))
}

pub fn is_user_verified(user_data: &UserData) -> bool {
    matches!(user_data.verification_status, VerificationStatus::Verified)
}

pub fn ensure_user_verified(user_data: &UserData) -> Result<(), Error> {
    if !is_user_verified(user_data) {
        return Err(Error::VerificationRequired);
    }
    Ok(())
}

pub fn verify_admin(env: &Env) -> Result<(), Error> {
    let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
    admin.require_auth();
    Ok(())
}

pub fn ensure_contract_active(env: &Env) -> Result<(), Error> {
    if AdminModule::is_contract_paused(env) {
        return Err(Error::ContractPaused);
    }
    Ok(())
}
