use crate::helpers::verify_admin;
use crate::interface::AdminOperations;
use crate::types::{DataKey, Error, LevelRequirements, Milestone, RewardRates};
use soroban_sdk::{Address, Env};

pub struct AdminModule;

impl AdminOperations for AdminModule {
    fn initialize(
        env: Env,
        admin: Address,
        reward_token: Address,
        level_requirements: LevelRequirements,
    ) -> Result<(), Error> {
        // Check if contract is already initialized
        if env.storage().persistent().has(&DataKey::Admin) {
            return Err(Error::AlreadyInitialized);
        }

        // Store admin address
        env.storage().persistent().set(&DataKey::Admin, &admin);

        // Initialize contract as active
        env.storage()
            .persistent()
            .set(&DataKey::ContractPaused, &false);

        // Store reward token
        env.storage()
            .persistent()
            .set(&DataKey::RewardToken, &reward_token);

        // Store level requirements
        env.storage()
            .persistent()
            .set(&DataKey::LevelRequirements, &level_requirements);

        Ok(())
    }

    fn set_reward_rates(env: Env, rates: RewardRates) -> Result<(), Error> {
        verify_admin(&env)?;
        env.storage()
            .persistent()
            .set(&DataKey::RewardRates, &rates);
        Ok(())
    }

    fn add_milestone(env: Env, milestone: Milestone) -> Result<(), Error> {
        verify_admin(&env)?;

        // Find next available milestone ID
        let mut next_id = 0;
        while env.storage().persistent().has(&DataKey::Milestone(next_id)) {
            next_id += 1;
        }

        // Store the milestone with its ID
        env.storage()
            .persistent()
            .set(&DataKey::Milestone(next_id), &milestone);

        Ok(())
    }

    fn remove_milestone(env: Env, milestone_id: u32) -> Result<(), Error> {
        verify_admin(&env)?;

        if !env
            .storage()
            .persistent()
            .has(&DataKey::Milestone(milestone_id))
        {
            return Err(Error::MilestoneNotFound);
        }

        env.storage()
            .persistent()
            .remove(&DataKey::Milestone(milestone_id));
        Ok(())
    }

    fn update_milestone(
        env: Env,
        milestone_id: u32,
        new_milestone: Milestone,
    ) -> Result<(), Error> {
        verify_admin(&env)?;

        if !env
            .storage()
            .persistent()
            .has(&DataKey::Milestone(milestone_id))
        {
            return Err(Error::MilestoneNotFound);
        }

        env.storage()
            .persistent()
            .set(&DataKey::Milestone(milestone_id), &new_milestone);

        Ok(())
    }

    fn pause_contract(env: Env) -> Result<(), Error> {
        verify_admin(&env)?;
        env.storage()
            .persistent()
            .set(&DataKey::ContractPaused, &true);
        Ok(())
    }

    fn resume_contract(env: Env) -> Result<(), Error> {
        verify_admin(&env)?;
        env.storage()
            .persistent()
            .set(&DataKey::ContractPaused, &false);
        Ok(())
    }

    fn transfer_admin(env: Env, new_admin: Address) -> Result<(), Error> {
        verify_admin(&env)?;
        env.storage().persistent().set(&DataKey::Admin, &new_admin);
        Ok(())
    }

    fn set_level_requirements(env: Env, requirements: LevelRequirements) -> Result<(), Error> {
        verify_admin(&env)?;

        // Validate that higher levels have stricter requirements
        if !Self::validate_level_requirements(&requirements) {
            return Err(Error::InvalidLevelRequirements);
        }

        env.storage()
            .persistent()
            .set(&DataKey::LevelRequirements, &requirements);
        Ok(())
    }

    fn set_reward_token(env: Env, token: Address) -> Result<(), Error> {
        verify_admin(&env)?;
        env.storage()
            .persistent()
            .set(&DataKey::RewardToken, &token);
        Ok(())
    }
}

// Helper functions
impl AdminModule {
    pub fn is_contract_paused(env: &Env) -> bool {
        env.storage()
            .persistent()
            .get(&DataKey::ContractPaused)
            .unwrap_or(false)
    }

    fn validate_level_requirements(requirements: &LevelRequirements) -> bool {
        // Ensure Gold requirements are higher than Silver
        if requirements.gold.required_direct_referrals
            < requirements.silver.required_direct_referrals
            || requirements.gold.required_team_size < requirements.silver.required_team_size
            || requirements.gold.required_total_rewards < requirements.silver.required_total_rewards
        {
            return false;
        }

        // Ensure Platinum requirements are higher than Gold
        if requirements.platinum.required_direct_referrals
            < requirements.gold.required_direct_referrals
            || requirements.platinum.required_team_size < requirements.gold.required_team_size
            || requirements.platinum.required_total_rewards
                < requirements.gold.required_total_rewards
        {
            return false;
        }

        true
    }
}
