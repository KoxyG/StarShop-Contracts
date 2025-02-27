use crate::admin::AdminModule;
use crate::level::LevelManagementModule;
use crate::referral::ReferralModule;
use crate::types::{DataKey, Error, Milestone, MilestoneRequirement, RewardRates};
use soroban_sdk::token::Client as TokenClient;
use soroban_sdk::{Address, Env, Vec};
pub struct RewardModule;
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

    /// Get total distributed rewards
    fn get_total_distributed_rewards(env: Env) -> Result<i128, Error>;
}

impl RewardOperations for RewardModule {
    fn distribute_rewards(env: Env, user: Address, amount: i128) -> Result<(), Error> {
        AdminModule::ensure_contract_active(&env)?;
        AdminModule::verify_admin(&env)?;

        // Get user data and verify
        let user_data = ReferralModule::get_user_data(&env, &user)?;
        ReferralModule::ensure_user_verified(&user_data)?;

        // Verify amount is positive
        if amount <= 0 {
            return Err(Error::InvalidAmount);
        }

        let mut total_distributed = 0;

        // Get reward rates
        let rates: RewardRates = env
            .storage()
            .instance()
            .get(&DataKey::RewardRates)
            .ok_or(Error::InvalidRewardRates)?;

        // Check if amount exceeds max reward per referral
        if amount > rates.max_reward_per_referral {
            return Err(Error::MaxRewardExceeded);
        }

        // First reward the user themselves
        let mut user_data = ReferralModule::get_user_data(&env, &user)?;
        user_data.pending_rewards += amount;
        user_data.total_rewards += amount;
        total_distributed += amount;

        // Update storage for user
        env.storage()
            .persistent()
            .set(&DataKey::User(user.clone()), &user_data);

        // Calculate and distribute rewards to upline (up to 3 levels)
        let mut current_user = user_data.clone();
        let mut remaining_levels = 3;

        while let Some(upline_address) = current_user.referrer {
            if remaining_levels == 0 {
                break;
            }

            let mut upline_data = ReferralModule::get_user_data(&env, &upline_address)?;

            // Calculate reward based on level
            let reward_rate = match remaining_levels {
                3 => rates.level1,
                2 => rates.level2,
                1 => rates.level3,
                _ => 0,
            };

            let reward_amount = (amount * reward_rate as i128) / 10000; // Convert basis points to actual percentage
            upline_data.pending_rewards += reward_amount;
            upline_data.total_rewards += reward_amount;
            total_distributed += reward_amount;

            // Check and update level
            LevelManagementModule::check_and_update_level(&env, &mut upline_data)?;

            // Update storage (only once)
            env.storage()
                .persistent()
                .set(&DataKey::User(upline_address.clone()), &upline_data);

            current_user = upline_data;
            remaining_levels -= 1;
        }

        // Update total distributed rewards
        RewardModule::add_distributed_rewards(&env, total_distributed);

        Ok(())
    }

    fn claim_rewards(env: Env, user: Address) -> Result<i128, Error> {
        AdminModule::ensure_contract_active(&env)?;
        user.require_auth();

        let mut user_data = ReferralModule::get_user_data(&env, &user)?;
        ReferralModule::ensure_user_verified(&user_data)?;

        if user_data.pending_rewards <= 0 {
            return Err(Error::InsufficientRewards);
        }

        let amount = user_data.pending_rewards;
        user_data.pending_rewards = 0;

        let reward_token = env
            .storage()
            .instance()
            .get(&DataKey::RewardToken)
            .ok_or(Error::InvalidRewardToken)?;

        // Transfer tokens to user
        let token = TokenClient::new(&env, &reward_token);
        token.transfer(&env.current_contract_address(), &user, &amount);

        // Update storage
        env.storage()
            .persistent()
            .set(&DataKey::User(user), &user_data);

        Ok(amount)
    }

    fn get_pending_rewards(env: Env, user: Address) -> Result<i128, Error> {
        let user_data = ReferralModule::get_user_data(&env, &user)?;
        Ok(user_data.pending_rewards)
    }

    fn get_total_rewards(env: Env, user: Address) -> Result<i128, Error> {
        let user_data = ReferralModule::get_user_data(&env, &user)?;
        Ok(user_data.total_rewards)
    }

    fn check_and_reward_milestone(env: Env, user: Address) -> Result<(), Error> {
        user.require_auth();

        let user_data = ReferralModule::get_user_data(&env, &user)?;
        ReferralModule::ensure_user_verified(&user_data)?;

        let mut milestone_id = 0;
        while env
            .storage()
            .instance()
            .has(&DataKey::Milestone(milestone_id))
        {
            // check if milestone already achieved
            if RewardModule::has_achieved_milestone(&env, &user, milestone_id) {
                milestone_id += 1;
                continue;
            }

            let milestone: Milestone = env
                .storage()
                .instance()
                .get(&DataKey::Milestone(milestone_id))
                .unwrap();

            // Check if user meets milestone requirements
            let requirement_met = match milestone.requirement {
                MilestoneRequirement::DirectReferrals(required) => {
                    user_data.direct_referrals.len() as u32 >= required
                }
                MilestoneRequirement::TeamSize(required) => user_data.team_size >= required,
                MilestoneRequirement::TotalRewards(required) => user_data.total_rewards >= required,
                MilestoneRequirement::ActiveDays(required) => {
                    let current_time = env.ledger().timestamp();
                    (current_time - user_data.join_date) / (24 * 60 * 60) >= required
                }
            };

            // If requirement met and user level matches or exceeds required level
            if requirement_met && (user_data.level >= milestone.required_level) {
                // Distribute milestone reward
                let mut updated_user = user_data.clone();
                updated_user.pending_rewards += milestone.reward_amount;
                updated_user.total_rewards += milestone.reward_amount;

                // Update user data
                env.storage()
                    .persistent()
                    .set(&DataKey::User(user.clone()), &updated_user);

                // Update total distributed rewards
                RewardModule::add_distributed_rewards(&env, milestone.reward_amount);

                // Mark milestone as achieved for this user
                let mut updated_achieved = env
                    .storage()
                    .persistent()
                    .get::<_, Vec<u32>>(&DataKey::UserAchievedMilestones(user.clone()))
                    .unwrap_or_else(|| Vec::new(&env));

                updated_achieved.push_back(milestone_id);

                env.storage().persistent().set(
                    &DataKey::UserAchievedMilestones(user.clone()),
                    &updated_achieved,
                );

                return Ok(());
            }

            milestone_id += 1;
        }

        Ok(())
    }

    fn get_total_distributed_rewards(env: Env) -> Result<i128, Error> {
        Ok(env
            .storage()
            .instance()
            .get::<_, i128>(&DataKey::TotalDistributedRewards)
            .unwrap_or(0))
    }
}

// Helper functions
impl RewardModule {
    pub fn has_achieved_milestone(env: &Env, user: &Address, milestone_id: u32) -> bool {
        env.storage()
            .persistent()
            .get::<_, Vec<u32>>(&DataKey::UserAchievedMilestones(user.clone()))
            .map_or(false, |achieved| achieved.contains(&milestone_id))
    }

    pub fn add_distributed_rewards(env: &Env, amount: i128) {
        let current = env
            .storage()
            .instance()
            .get::<_, i128>(&DataKey::TotalDistributedRewards)
            .unwrap_or_default();

        env.storage()
            .instance()
            .set(&DataKey::TotalDistributedRewards, &(current + amount));
    }
}
