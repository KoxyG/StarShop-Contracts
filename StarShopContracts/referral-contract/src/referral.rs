use crate::helpers::{ensure_contract_active, ensure_user_verified, get_user_data, user_exists};
use crate::level::LevelManagementModule;
use crate::rewards::RewardModule;
use crate::rewards::RewardOperations;
use crate::types::{DataKey, Error, UserData, UserLevel, VerificationStatus};
use crate::verification::VerificationModule;
use soroban_sdk::{Address, Env, String, Vec};

pub struct ReferralModule;

pub trait ReferralOperations {
    /// Initialize contract
    fn initialize(env: &Env, admin: &Address) -> Result<(), Error>;

    /// Register new user with referral
    fn register_with_referral(
        env: Env,
        user: Address,
        referrer_address: Address,
        identity_proof: String,
    ) -> Result<(), Error>;

    /// Check if user is verified
    fn is_user_verified(env: Env, user: Address) -> Result<bool, Error>;

    /// Check if user is registered
    fn is_user_registered(env: Env, user: Address) -> Result<bool, Error>;

    /// Get user's information
    fn get_user_info(env: Env, user: Address) -> Result<UserData, Error>;

    /// Get user's direct referrals
    fn get_direct_referrals(env: Env, user: Address) -> Result<Vec<Address>, Error>;

    /// Get user's team size (all levels)
    fn get_team_size(env: Env, user: Address) -> Result<u32, Error>;

    /// Get user's level
    fn get_user_level(env: Env, user: Address) -> Result<UserLevel, Error>;

    /// Get total registered users
    fn get_total_users(env: Env) -> Result<u32, Error>;

    /// Get system statistics
    fn get_system_metrics(env: Env) -> Result<Vec<(String, i128)>, Error>;

    /// Get user conversion rates
    fn get_referral_conversion_rate(env: Env, user: Address) -> Result<u32, Error>;
}

impl ReferralOperations for ReferralModule {
    fn initialize(env: &Env, admin: &Address) -> Result<(), Error> {
        admin.require_auth();

        // Create new user data
        let user_data = UserData {
            address: admin.clone(),
            referrer: None,
            direct_referrals: Vec::new(&env),
            team_size: 0,
            pending_rewards: 0,
            total_rewards: 0,
            level: UserLevel::Basic,
            verification_status: VerificationStatus::Verified,
            identity_proof: String::from_str(&env, ""),
            join_date: env.ledger().timestamp(),
        };

        // Store user data
        env.storage()
            .persistent()
            .set(&DataKey::User(admin.clone()), &user_data);

        // Increment total users
        ReferralModule::increment_total_users(&env);

        Ok(())
    }

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
        let user_data = UserData {
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
        VerificationModule::add_to_pending_verifications(&env, &user);

        // Increment total users
        ReferralModule::increment_total_users(&env);

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

    fn get_user_level(env: Env, user: Address) -> Result<UserLevel, Error> {
        let user_data = get_user_data(&env, &user)?;
        Ok(user_data.level)
    }

    fn get_total_users(env: Env) -> Result<u32, Error> {
        Ok(env
            .storage()
            .instance()
            .get::<_, u32>(&DataKey::TotalUsers)
            .unwrap_or_default())
    }
    fn get_system_metrics(env: Env) -> Result<Vec<(String, i128)>, Error> {
        let mut metrics = Vec::new(&env);

        // Total users
        let total_users = Self::get_total_users(env.clone())? as i128;
        metrics.push_back((String::from_str(&env, "total_users"), total_users));

        // Total rewards
        let total_rewards = RewardModule::get_total_distributed_rewards(env.clone())?;
        metrics.push_back((
            String::from_str(&env, "total_distributed_rewards"),
            total_rewards,
        ));

        // Average reward per user
        let avg_reward = if total_users > 0 {
            total_rewards / total_users
        } else {
            0
        };
        metrics.push_back((
            String::from_str(&env, "average_reward_per_user"),
            avg_reward,
        ));

        Ok(metrics)
    }

    fn get_referral_conversion_rate(env: Env, user: Address) -> Result<u32, Error> {
        let user_data = get_user_data(&env, &user)?;

        if user_data.direct_referrals.len() == 0 {
            return Ok(0);
        }

        let mut verified_referrals = 0;
        for referral in user_data.direct_referrals.iter() {
            let referral_data = get_user_data(&env, &referral)?;
            if crate::helpers::is_user_verified(&referral_data) {
                verified_referrals += 1;
            }
        }

        // Calculate conversion rate as percentage (0-100)
        Ok((verified_referrals * 100) / user_data.direct_referrals.len() as u32)
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

    pub fn increment_total_users(env: &Env) {
        let current = env
            .storage()
            .instance()
            .get::<_, u32>(&DataKey::TotalUsers)
            .unwrap_or_default();

        env.storage()
            .instance()
            .set(&DataKey::TotalUsers, &(current + 1));
    }
}
