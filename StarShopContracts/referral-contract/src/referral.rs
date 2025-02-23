use crate::helpers::{ensure_contract_active, ensure_user_verified, get_user_data, user_exists};
use crate::interface::ReferralOperations;
use crate::level::LevelManagementModule;
use crate::metrics::MetricsModule;
use crate::types::{DataKey, Error, UserData, UserLevel, VerificationStatus};
use crate::verification::VerificationModule;
use soroban_sdk::{Address, Env, String, Vec};

pub struct ReferralModule;

impl ReferralOperations for ReferralModule {
    fn register_with_referral(
        env: Env,
        user: Address,
        referrer_address: Address,
        identity_proof: String,
    ) -> Result<(), Error> {
        ensure_contract_active(&env)?;
        user.require_auth();

        // Check if user already exists
        if user_exists(&env, &user) {
            return Err(Error::AlreadyRegistered);
        }

        // Check if referrer exists
        if !user_exists(&env, &referrer_address) {
            return Err(Error::ReferrerNotFound);
        }

        // Check if referrer is verified
        let referrer_data = get_user_data(&env, &referrer_address)?;
        ensure_user_verified(&referrer_data)?;

        // Create new user data
        let mut user_data = UserData {
            address: user.clone(),
            referrer: Some(referrer_address.clone()),
            direct_referrals: Vec::new(&env),
            team_size: 0,
            pending_rewards: 0,
            total_rewards: 0,
            level: UserLevel::Basic,
            verification_status: VerificationStatus::Pending,
            identity_proof: identity_proof.clone(),
            join_date: env.ledger().timestamp(),
        };

        // Store user data
        env.storage()
            .persistent()
            .set(&DataKey::User(user.clone()), &user_data);

        // Update referrer's direct referrals and team size
        Self::update_referrer_stats(&env, &referrer_address, &user)?;

        // Submit verification automatically
        VerificationModule::process_verification(&env, &mut user_data, &identity_proof)?;

        // Increment total users
        MetricsModule::increment_total_users(&env);

        Ok(())
    }

    fn is_user_verified(env: Env, user: Address) -> Result<bool, Error> {
        get_user_data(&env, &user)
            .map(|data| data.verification_status == VerificationStatus::Verified)
    }

    fn is_user_registered(env: Env, user: Address) -> Result<bool, Error> {
        Ok(user_exists(&env, &user))
    }

    fn get_user_info(env: Env, user: Address) -> Result<UserData, Error> {
        get_user_data(&env, &user)
    }

    fn get_direct_referrals(env: Env, user: Address) -> Result<Vec<Address>, Error> {
        let user_data = get_user_data(&env, &user)?;
        Ok(user_data.direct_referrals)
    }

    fn get_team_size(env: Env, user: Address) -> Result<u32, Error> {
        let user_data = get_user_data(&env, &user)?;
        Ok(user_data.team_size)
    }
}

// Helper functions
impl ReferralModule {
    fn update_referrer_stats(
        env: &Env,
        referrer: &Address,
        new_user: &Address,
    ) -> Result<(), Error> {
        let mut referrer_data = get_user_data(env, referrer)?;

        // Add to direct referrals
        referrer_data.direct_referrals.push_back(new_user.clone());

        // Update team size
        referrer_data.team_size += 1;

        // Check for level update
        LevelManagementModule::check_and_update_level(env, &mut referrer_data)?;

        // Store updated referrer data
        env.storage()
            .persistent()
            .set(&DataKey::User(referrer.clone()), &referrer_data);

        // Update upstream team sizes (for 3 levels)
        if let Some(upline) = &referrer_data.referrer {
            Self::update_upline_team_size(env, upline, 2)?;
        }

        Ok(())
    }

    fn update_upline_team_size(
        env: &Env,
        user: &Address,
        remaining_levels: u32,
    ) -> Result<(), Error> {
        if remaining_levels == 0 {
            return Ok(());
        }

        let mut user_data = get_user_data(env, user)?;
        user_data.team_size += 1;

        env.storage()
            .persistent()
            .set(&DataKey::User(user.clone()), &user_data);

        if let Some(upline) = user_data.referrer {
            Self::update_upline_team_size(env, &upline, remaining_levels - 1)?;
        }

        Ok(())
    }
}
