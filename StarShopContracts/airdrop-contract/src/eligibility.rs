use crate::{
    external::MetricProviderClient,
    types::{AirdropError, AirdropEvent, DataKey},
};
use soroban_sdk::{Address, Env, Symbol};

impl super::AirdropContract {
    /// Check if a user is eligible for an airdrop event.
    pub fn check_eligibility(
        &self,
        env: &Env,
        user: &Address,
        event_id: u64,
    ) -> Result<(), AirdropError> {
        user.require_auth();

        // Fetch the airdrop event
        let airdrop_event: AirdropEvent = env
            .storage()
            .persistent()
            .get(&DataKey::AirdropEvent(event_id))
            .ok_or(AirdropError::AirdropNotFound)?;

        // Check if the event is active and within time window
        if !airdrop_event.is_active {
            return Err(AirdropError::EventInactive);
        }
        let current_time = env.ledger().timestamp();
        if current_time < airdrop_event.start_time || current_time > airdrop_event.end_time {
            return Err(AirdropError::EventInactive);
        }

        // Check if the event is finalized
        if env
            .storage()
            .persistent()
            .get(&DataKey::EventStatus(event_id))
            .unwrap_or(false)
        {
            return Err(AirdropError::EventInactive);
        }

        // Check if the user has already claimed
        if env
            .storage()
            .persistent()
            .get(&DataKey::Claimed(event_id, user.clone()))
            .unwrap_or(false)
        {
            return Err(AirdropError::AlreadyClaimed);
        }

        // Iterate over conditions
        for (condition, required_value) in airdrop_event.conditions.iter() {
            // Validate condition
            if required_value == 0 {
                return Err(AirdropError::InvalidEventConfig);
            }

            // Fetch provider address from registry
            let provider_address = env
                .storage()
                .persistent()
                .get(&DataKey::ProviderRegistry(condition.clone()))
                .ok_or(AirdropError::ProviderNotConfigured)?;

            // Call the provider's get_metric function
            let client = MetricProviderClient::new(env, &provider_address);
            let user_metric = client.get_user_metric(user, &condition.clone());

            // Check if the metric meets the requirement
            if user_metric < required_value {
                return Err(AirdropError::UserNotEligible);
            }
        }

        // Emit event for transparency
        env.events().publish(
            (Symbol::new(env, "EligibilityChecked"), event_id, user),
            true,
        );

        Ok(())
    }
}
