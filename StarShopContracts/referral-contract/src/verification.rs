use crate::helpers::{ensure_contract_active, get_user_data, verify_admin};
use crate::types::{DataKey, Error, UserData, VerificationStatus};
use soroban_sdk::{Address, Env, String, Vec};

pub struct VerificationModule;

pub trait VerificationOperations {
    /// Submit verification documents for review
    fn submit_verification(env: Env, user: Address, identity_proof: String) -> Result<(), Error>;

    /// Admin approval of user verification
    fn approve_verification(env: Env, user: Address) -> Result<(), Error>;

    /// Admin rejection of user verification with reason
    fn reject_verification(env: Env, user: Address, reason: String) -> Result<(), Error>;

    /// Get user's verification status
    fn get_verification_status(env: Env, user: Address) -> Result<VerificationStatus, Error>;

    /// Get list of pending verifications
    fn get_pending_verifications(env: Env) -> Result<Vec<Address>, Error>;
}

impl VerificationOperations for VerificationModule {
    fn submit_verification(env: Env, user: Address, identity_proof: String) -> Result<(), Error> {
        ensure_contract_active(&env)?;
        user.require_auth();

        let mut user_data = get_user_data(&env, &user)?;
        Self::process_verification(&env, &mut user_data, &identity_proof)
    }

    fn approve_verification(env: Env, user: Address) -> Result<(), Error> {
        verify_admin(&env)?;

        let mut user_data = get_user_data(&env, &user)?;
        user_data.verification_status = VerificationStatus::Verified;

        env.storage()
            .persistent()
            .set(&DataKey::User(user.clone()), &user_data);
        Self::remove_from_pending_verifications(&env, &user);

        Ok(())
    }

    fn reject_verification(env: Env, user: Address, reason: String) -> Result<(), Error> {
        verify_admin(&env)?;

        let mut user_data = get_user_data(&env, &user)?;
        user_data.verification_status = VerificationStatus::Rejected(reason);

        env.storage()
            .persistent()
            .set(&DataKey::User(user.clone()), &user_data);
        Self::remove_from_pending_verifications(&env, &user);

        Ok(())
    }

    fn get_verification_status(env: Env, user: Address) -> Result<VerificationStatus, Error> {
        let user_data = get_user_data(&env, &user)?;
        Ok(user_data.verification_status)
    }

    fn get_pending_verifications(env: Env) -> Result<Vec<Address>, Error> {
        verify_admin(&env)?; //do we need this for a get function??

        Ok(env
            .storage()
            .instance()
            .get(&DataKey::PendingVerifications(Vec::new(&env)))
            .unwrap_or_else(|| Vec::new(&env)))
    }
}

// Helper functions
impl VerificationModule {
    pub fn process_verification(
        env: &Env,
        user: &mut UserData,
        identity_proof: &String,
    ) -> Result<(), Error> {
        match user.verification_status {
            VerificationStatus::Verified => return Err(Error::AlreadyVerified),
            VerificationStatus::Pending => return Err(Error::AlreadyVerified),
            VerificationStatus::Rejected(_) => (),
        }

        user.verification_status = VerificationStatus::Pending;
        user.identity_proof = identity_proof.clone();

        env.storage()
            .persistent()
            .set(&DataKey::User(user.address.clone()), user);
        Self::add_to_pending_verifications(&env, &user.address);

        Ok(())
    }

    //add user to pending verifications
    pub fn add_to_pending_verifications(env: &Env, user: &Address) {
        let mut pending = env
            .storage()
            .instance()
            .get::<_, Vec<Address>>(&DataKey::PendingVerifications(Vec::new(env)))
            .unwrap_or_else(|| Vec::new(env));

        pending.push_back(user.clone());
        env.storage()
            .instance()
            .set(&DataKey::PendingVerifications(Vec::new(env)), &pending);
    }

    fn remove_from_pending_verifications(env: &Env, user: &Address) {
        let pending = env
            .storage()
            .instance()
            .get::<_, Vec<Address>>(&DataKey::PendingVerifications(Vec::new(env)))
            .unwrap_or_else(|| Vec::new(env));

        // Remove the user from pending verifications
        let mut new_pending = Vec::new(env);
        for addr in pending.iter() {
            if &addr != user {
                new_pending.push_back(addr);
            }
        }

        env.storage()
            .instance()
            .set(&DataKey::PendingVerifications(Vec::new(env)), &new_pending);
    }
}
