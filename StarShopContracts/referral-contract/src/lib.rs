#![no_std]
use soroban_sdk::{
    contract, contracterror, contractimpl, panic_with_error, Address, Env, String, Symbol, Vec,
};

use admin::*;
use referral::*;
use rewards::*;
use types::*;
use verification::*;

mod admin;
mod level;
mod referral;
mod rewards;
pub mod types;
mod verification;

// Define ProviderError as per airdrop's external.rs
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum ProviderError {
    InvalidUser = 1,
    MetricNotSupported = 2,
}

// Define MetricProvider trait as per airdrop's external.rs
pub trait MetricProvider {
    fn get_user_metric(env: Env, user: Address, metric: Symbol) -> Result<u64, ProviderError>;
}

#[contract]
pub struct ReferralContract;

#[contractimpl]
impl MetricProvider for ReferralContract {
    fn get_user_metric(env: Env, user: Address, metric: Symbol) -> Result<u64, ProviderError> {
        // Check if user exists
        if !ReferralModule::user_exists(&env, &user) {
            panic_with_error!(&env, ProviderError::InvalidUser);
        }

        let user_data =
            ReferralModule::get_user_data(&env, &user).map_err(|_| ProviderError::InvalidUser)?;

        // Define metric symbols
        let referrals = Symbol::new(&env, "referrals");
        let team_size = Symbol::new(&env, "team_size");
        let total_rewards = Symbol::new(&env, "total_rewards");
        let user_level = Symbol::new(&env, "user_level");
        let conversion_rate = Symbol::new(&env, "conversion_rate");
        let active_days = Symbol::new(&env, "active_days");
        let is_verified = Symbol::new(&env, "is_verified");

        // Match metric and return corresponding value
        let result = match metric.clone() {
            m if m == referrals => user_data.direct_referrals.len() as u64,
            m if m == team_size => user_data.team_size as u64,
            m if m == total_rewards => {
                // Scale i128 to u64, dividing by 10^4
                let scaled = user_data.total_rewards / 10_000;
                if scaled > u64::MAX as i128 {
                    u64::MAX
                } else {
                    scaled as u64
                }
            }
            m if m == user_level => match user_data.level {
                UserLevel::Basic => 0,
                UserLevel::Silver => 1,
                UserLevel::Gold => 2,
                UserLevel::Platinum => 3,
            },
            m if m == conversion_rate => {
                ReferralModule::get_referral_conversion_rate(env.clone(), user.clone())
                    .map_err(|_| ProviderError::InvalidUser)? as u64
            }
            m if m == active_days => {
                let current_time = env.ledger().timestamp();
                (current_time - user_data.join_date) / (24 * 60 * 60)
            }
            m if m == is_verified => {
                matches!(user_data.verification_status, VerificationStatus::Verified) as u64
            }
            _ => return Err(ProviderError::MetricNotSupported),
        };

        // Emit event for transparency
        env.events()
            .publish((Symbol::new(&env, "MetricQueried"), user, metric), result);

        Ok(result)
    }
}

#[contractimpl]
impl ReferralContract {
    // Existing functions remain unchanged
    pub fn initialize(env: Env, admin: Address, reward_token: Address) -> Result<(), Error> {
        let default_requirements = LevelRequirements {
            silver: LevelCriteria {
                required_direct_referrals: 5,
                required_team_size: 15,
                required_total_rewards: 1000,
            },
            gold: LevelCriteria {
                required_direct_referrals: 10,
                required_team_size: 50,
                required_total_rewards: 5000,
            },
            platinum: LevelCriteria {
                required_direct_referrals: 20,
                required_team_size: 100,
                required_total_rewards: 20000,
            },
        };
        ReferralModule::initialize(&env, &admin)?;
        AdminModule::initialize(env, admin, reward_token, default_requirements)
    }

    pub fn set_reward_rates(env: Env, rates: RewardRates) -> Result<(), Error> {
        AdminModule::set_reward_rates(env, rates)
    }

    pub fn get_admin(env: Env) -> Result<Address, Error> {
        AdminModule::get_admin(env)
    }

    pub fn add_milestone(env: Env, milestone: Milestone) -> Result<(), Error> {
        AdminModule::add_milestone(env, milestone)
    }

    pub fn remove_milestone(env: Env, milestone_id: u32) -> Result<(), Error> {
        AdminModule::remove_milestone(env, milestone_id)
    }

    pub fn update_milestone(
        env: Env,
        milestone_id: u32,
        milestone: Milestone,
    ) -> Result<(), Error> {
        AdminModule::update_milestone(env, milestone_id, milestone)
    }

    pub fn pause_contract(env: Env) -> Result<(), Error> {
        AdminModule::pause_contract(env)
    }

    pub fn resume_contract(env: Env) -> Result<(), Error> {
        AdminModule::resume_contract(env)
    }

    pub fn get_paused_state(env: Env) -> Result<bool, Error> {
        AdminModule::get_paused_state(env)
    }

    pub fn transfer_admin(env: Env, new_admin: Address) -> Result<(), Error> {
        AdminModule::transfer_admin(env, new_admin)
    }

    pub fn set_reward_token(env: Env, token: Address) -> Result<(), Error> {
        AdminModule::set_reward_token(env, token)
    }

    pub fn set_level_requirements(env: Env, requirements: LevelRequirements) -> Result<(), Error> {
        AdminModule::set_level_requirements(env, requirements)
    }

    pub fn submit_verification(
        env: Env,
        user: Address,
        identity_proof: String,
    ) -> Result<(), Error> {
        VerificationModule::submit_verification(env, user, identity_proof)
    }

    pub fn approve_verification(env: Env, user: Address) -> Result<(), Error> {
        VerificationModule::approve_verification(env, user)
    }

    pub fn reject_verification(env: Env, user: Address, reason: String) -> Result<(), Error> {
        VerificationModule::reject_verification(env, user, reason)
    }

    pub fn get_verification_status(env: Env, user: Address) -> Result<VerificationStatus, Error> {
        VerificationModule::get_verification_status(env, user)
    }

    pub fn get_pending_verifications(env: Env) -> Result<Vec<Address>, Error> {
        VerificationModule::get_pending_verifications(env)
    }

    pub fn register_with_referral(
        env: Env,
        user: Address,
        referrer_address: Address,
        identity_proof: String,
    ) -> Result<(), Error> {
        ReferralModule::register_with_referral(env, user, referrer_address, identity_proof)
    }

    pub fn is_user_verified(env: Env, user: Address) -> Result<bool, Error> {
        ReferralModule::is_user_verified(env, user)
    }

    pub fn is_user_registered(env: Env, user: Address) -> Result<bool, Error> {
        ReferralModule::is_user_registered(env, user)
    }

    pub fn get_user_info(env: Env, user: Address) -> Result<UserData, Error> {
        ReferralModule::get_user_info(env, user)
    }

    pub fn get_direct_referrals(env: Env, user: Address) -> Result<Vec<Address>, Error> {
        ReferralModule::get_direct_referrals(env, user)
    }

    pub fn get_team_size(env: Env, user: Address) -> Result<u32, Error> {
        ReferralModule::get_team_size(env, user)
    }

    pub fn distribute_rewards(env: Env, user: Address, amount: i128) -> Result<(), Error> {
        RewardModule::distribute_rewards(env, user, amount)
    }

    pub fn claim_rewards(env: Env, user: Address) -> Result<i128, Error> {
        RewardModule::claim_rewards(env, user)
    }

    pub fn get_pending_rewards(env: Env, user: Address) -> Result<i128, Error> {
        RewardModule::get_pending_rewards(env, user)
    }

    pub fn get_total_rewards(env: Env, user: Address) -> Result<i128, Error> {
        RewardModule::get_total_rewards(env, user)
    }

    pub fn check_and_reward_milestone(env: Env, user: Address) -> Result<(), Error> {
        RewardModule::check_and_reward_milestone(env, user)
    }

    pub fn get_total_users(env: Env) -> Result<u32, Error> {
        ReferralModule::get_total_users(env)
    }

    pub fn get_total_distributed_rewards(env: Env) -> Result<i128, Error> {
        RewardModule::get_total_distributed_rewards(env)
    }

    pub fn get_system_metrics(env: Env) -> Result<Vec<(String, i128)>, Error> {
        ReferralModule::get_system_metrics(env)
    }

    pub fn get_referral_conversion_rate(env: Env, user: Address) -> Result<u32, Error> {
        ReferralModule::get_referral_conversion_rate(env, user)
    }

    pub fn get_user_level(env: Env, user: Address) -> Result<UserLevel, Error> {
        ReferralModule::get_user_level(env, user)
    }
}

#[cfg(test)]
mod test;
