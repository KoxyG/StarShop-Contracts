use crate::helpers::get_user_data;
use crate::interface::MetricsOperations;
use crate::types::{DataKey, Error};
use soroban_sdk::{Address, Env, String, Vec};

pub struct MetricsModule;

impl MetricsOperations for MetricsModule {
    fn get_total_users(env: Env) -> Result<u32, Error> {
        Ok(env
            .storage()
            .persistent()
            .get(&DataKey::TotalUsers)
            .unwrap_or(0))
    }

    fn get_total_distributed_rewards(env: Env) -> Result<i128, Error> {
        Ok(env
            .storage()
            .persistent()
            .get(&DataKey::TotalDistributedRewards)
            .unwrap_or(0))
    }

    fn get_system_metrics(env: Env) -> Result<Vec<(String, i128)>, Error> {
        let mut metrics = Vec::new(&env);

        // Total users
        let total_users = Self::get_total_users(env.clone())? as i128;
        metrics.push_back((String::from_str(&env, "total_users"), total_users));

        // Total rewards
        let total_rewards = Self::get_total_distributed_rewards(env.clone())?;
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
impl MetricsModule {
    pub fn increment_total_users(env: &Env) {
        let current = env
            .storage()
            .persistent()
            .get(&DataKey::TotalUsers)
            .unwrap_or(0);
        env.storage()
            .persistent()
            .set(&DataKey::TotalUsers, &(current + 1));
    }

    pub fn add_distributed_rewards(env: &Env, amount: i128) {
        let current = env
            .storage()
            .persistent()
            .get(&DataKey::TotalDistributedRewards)
            .unwrap_or(0);
        env.storage()
            .persistent()
            .set(&DataKey::TotalDistributedRewards, &(current + amount));
    }
}
