use crate::{
    tracking::AirdropManager,
    types::{AirdropError, AirdropEvent, DataKey, UserData},
};
use soroban_sdk::{Address, Env};

pub struct EligibilityManager<'a> {
    env: &'a Env,
}

impl<'a> EligibilityManager<'a> {
    /// Creates a new EligibilityManager instance.
    pub fn new(env: &'a Env) -> Self {
        Self { env }
    }

    /// Checks if a user is eligible for an airdrop event.
    ///
    /// # Arguments
    /// * `user` - The address of the user.
    /// * `event_id` - The ID of the airdrop event.
    ///
    /// # Returns
    /// * `Ok(())` if the user is eligible.
    /// * `Err(AirdropError)` if the airdrop is not found or the user is not eligible.
    pub fn check_eligibility(&self, user: &Address, event_id: u64) -> Result<(), AirdropError> {
        // Retrieve the airdrop event
        let airdrop_event: AirdropEvent = self
            .env
            .storage()
            .persistent()
            .get(&DataKey::AirdropEvent(event_id))
            .ok_or(AirdropError::AirdropNotFound)?;

        // Get user data
        let user_data: UserData = AirdropManager::new(self.env).get_user_data(user);

        // Check each condition in the event
        for (condition_key, min_value) in airdrop_event.conditions.iter() {
            let user_value = user_data.metrics.get(condition_key).unwrap_or(0);
            if user_value < min_value {
                return Err(AirdropError::UserNotEligible);
            }
        }

        Ok(())
    }
}
