use crate::types::{DataKey, Error, LevelCriteria, LevelRequirements, UserData, UserLevel};
use soroban_sdk::Env;

pub struct LevelManagementModule;

impl LevelManagementModule {
    pub fn check_and_update_level(env: &Env, user_data: &mut UserData) -> Result<bool, Error> {
        let requirements: LevelRequirements = env
            .storage()
            .persistent()
            .get(&DataKey::LevelRequirements)
            .ok_or(Error::InvalidLevelRequirements)?;

        let new_level = Self::calculate_eligible_level(user_data, &requirements);

        if new_level > user_data.level {
            user_data.level = new_level;
            return Ok(true);
        }

        Ok(false)
    }

    fn calculate_eligible_level(
        user_data: &UserData,
        requirements: &LevelRequirements,
    ) -> UserLevel {
        // Check Platinum requirements
        if Self::meets_criteria(user_data, &requirements.platinum) {
            return UserLevel::Platinum;
        }

        // Check Gold requirements
        if Self::meets_criteria(user_data, &requirements.gold) {
            return UserLevel::Gold;
        }

        // Check Silver requirements
        if Self::meets_criteria(user_data, &requirements.silver) {
            return UserLevel::Silver;
        }

        UserLevel::Basic
    }

    fn meets_criteria(user_data: &UserData, criteria: &LevelCriteria) -> bool {
        user_data.direct_referrals.len() as u32 >= criteria.required_direct_referrals
            && user_data.team_size >= criteria.required_team_size
            && user_data.total_rewards >= criteria.required_total_rewards
    }
}
