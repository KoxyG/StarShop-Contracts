use crate::types::{
    Error, LevelRequirements, Milestone, RewardRates, UserData, UserLevel, VerificationStatus,
};
use soroban_sdk::{Address, Env, String, Vec};

/// Handles verification operations for users
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

/// Manages referral operations and relationships
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
}

/// Handles reward calculations and distributions
pub trait RewardOperations {
    /// Distribute rewards for a referral
    fn distribute_rewards(env: Env, user: Address, amount: i128) -> Result<(), Error>;

    /// Claim accumulated rewards
    fn claim_rewards(env: Env, user: Address) -> Result<i128, Error>;

    /// Get pending rewards balance
    fn get_pending_rewards(env: Env, user: Address) -> Result<i128, Error>;

    /// Get total rewards earned
    fn get_total_rewards(env: Env, user: Address) -> Result<i128, Error>;

    /// Check if milestone achieved and distribute rewards
    fn check_and_reward_milestone(env: Env, user: Address) -> Result<(), Error>;
}

/// Manages administrative operations
pub trait AdminOperations {
    /// Initialize contract with admin address
    fn initialize(
        env: Env,
        admin: Address,
        reward_token: Address,
        level_requirements: LevelRequirements,
    ) -> Result<(), Error>;

    /// get admin address
    fn get_admin(env: Env) -> Result<Address, Error>;

    /// Set reward rates for different levels
    fn set_reward_rates(env: Env, rates: RewardRates) -> Result<(), Error>;

    /// Set level requirements for different levels
    fn set_level_requirements(env: Env, requirements: LevelRequirements) -> Result<(), Error>;

    /// Set reward token
    fn set_reward_token(env: Env, token: Address) -> Result<(), Error>;

    /// Add new milestone
    fn add_milestone(env: Env, milestone: Milestone) -> Result<(), Error>;

    /// Remove existing milestone
    fn remove_milestone(env: Env, milestone_id: u32) -> Result<(), Error>;

    /// Update existing milestone
    fn update_milestone(env: Env, milestone_id: u32, milestone: Milestone) -> Result<(), Error>;

    /// Pause contract operations (emergency)
    fn pause_contract(env: Env) -> Result<(), Error>;

    /// Resume contract operations
    fn resume_contract(env: Env) -> Result<(), Error>;

    /// Check if contract is paused
    fn get_paused_state(env: Env) -> Result<bool, Error>;

    /// Transfer admin rights to new address
    fn transfer_admin(env: Env, new_admin: Address) -> Result<(), Error>;
}

/// Handles system metrics and monitoring
pub trait MetricsOperations {
    /// Get total registered users
    fn get_total_users(env: Env) -> Result<u32, Error>;

    /// Get total distributed rewards
    fn get_total_distributed_rewards(env: Env) -> Result<i128, Error>;

    /// Get system statistics
    fn get_system_metrics(env: Env) -> Result<Vec<(String, i128)>, Error>;

    /// Get user conversion rates
    fn get_referral_conversion_rate(env: Env, user: Address) -> Result<u32, Error>;
}
