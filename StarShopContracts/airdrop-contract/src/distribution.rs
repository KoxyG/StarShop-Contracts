use crate::types::{AirdropError, AirdropEvent, DataKey, EventStats};
use soroban_sdk::{Address, Env, Symbol, token};

impl super::AirdropContract {
    /// Transfer tokens from the contract to a user.
    fn transfer_tokens(
        &self,
        env: &Env,
        token_address: &Address,
        to: &Address,
        amount: u64,
    ) -> Result<(), AirdropError> {
        // Validate token address
        if token_address == &Address::zero(env) {
            return Err(AirdropError::InvalidTokenConfig);
        }

        let token_client = token::TokenClient::new(env, token_address);
        let contract_address = env.current_contract_address();
        let contract_balance = token_client.balance(&contract_address);
        if contract_balance < amount as i128 {
            return Err(AirdropError::InsufficientContractBalance);
        }

        // Perform transfer
        token_client.transfer(&contract_address, to, &(amount as i128));

        // Verify transfer (ensure balance updated)
        let new_balance = token_client.balance(&contract_address);
        if new_balance != contract_balance - amount as i128 {
            return Err(AirdropError::TokenTransferFailed);
        }

        Ok(())
    }

    /// Handle individual user airdrop claim.
    fn distribute_tokens(
        &self,
        env: &Env,
        user: &Address,
        event_id: u64,
    ) -> Result<(), AirdropError> {
        user.require_auth();

        // 1. Fetch and validate event
        let airdrop_event: AirdropEvent = env
            .storage()
            .persistent()
            .get(&DataKey::AirdropEvent(event_id))
            .ok_or(AirdropError::AirdropNotFound)?;

        // Check event status and time window
        if !airdrop_event.is_active {
            return Err(AirdropError::EventInactive);
        }
        let current_time = env.ledger().timestamp();
        if current_time < airdrop_event.start_time || current_time > airdrop_event.end_time {
            return Err(AirdropError::EventInactive);
        }
        if env
            .storage()
            .persistent()
            .get(&DataKey::EventStatus(event_id))
            .unwrap_or(false)
        {
            return Err(AirdropError::EventInactive);
        }

        // 2. Validate amount
        if airdrop_event.amount == 0 {
            return Err(AirdropError::InvalidAmount);
        }

        // 3. Check caps
        let mut stats: EventStats = env
            .storage()
            .persistent()
            .get(&DataKey::EventStats(event_id))
            .unwrap_or(EventStats {
                recipient_count: 0,
                total_distributed: 0,
            });
        if let Some(max_users) = airdrop_event.max_users {
            if stats.recipient_count >= max_users {
                return Err(AirdropError::CapExceeded);
            }
        }
        if let Some(max_total) = airdrop_event.max_total_amount {
            if stats.total_distributed + airdrop_event.amount > max_total {
                return Err(AirdropError::CapExceeded);
            }
        }

        // 4. Check if user already claimed
        if self.has_claimed(env, user, event_id) {
            return Err(AirdropError::AlreadyClaimed);
        }

        // 5. Check eligibility
        self.check_eligibility(env, user, event_id)?;

        // 6. Transfer tokens
        self.transfer_tokens(
            env,
            &airdrop_event.token_address,
            user,
            airdrop_event.amount,
        )?;

        // 7. Update stats and mark claimed
        stats.recipient_count += 1;
        stats.total_distributed += airdrop_event.amount;
        env.storage()
            .persistent()
            .set(&DataKey::EventStats(event_id), &stats);
        self.mark_claimed(env, user, event_id);

        // 8. Emit event
        env.events().publish(
            (
                Symbol::new(env, "Claimed"),
                event_id,
                user.clone(),
                airdrop_event.name.clone(),
            ),
            (
                airdrop_event.token_address.clone(),
                airdrop_event.amount,
                current_time,
            ),
        );

        Ok(())
    }

    /// Admin-triggered batch distribution to multiple users.
    fn distribute_batch(
        &self,
        env: &Env,
        admin: &Address,
        event_id: u64,
        users: soroban_sdk::Vec<Address>,
    ) -> Result<(), AirdropError> {
        admin.require_auth();
        if !self.is_admin(env, admin) {
            return Err(AirdropError::Unauthorized);
        }

        // Fetch and validate event
        let airdrop_event: AirdropEvent = env
            .storage()
            .persistent()
            .get(&DataKey::AirdropEvent(event_id))
            .ok_or(AirdropError::AirdropNotFound)?;

        // Check event status and time window
        if !airdrop_event.is_active {
            return Err(AirdropError::EventInactive);
        }
        let current_time = env.ledger().timestamp();
        if current_time < airdrop_event.start_time || current_time > airdrop_event.end_time {
            return Err(AirdropError::EventInactive);
        }
        if env
            .storage()
            .persistent()
            .get(&DataKey::EventStatus(event_id))
            .unwrap_or(false)
        {
            return Err(AirdropError::EventInactive);
        }

        // Validate amount
        if airdrop_event.amount == 0 {
            return Err(AirdropError::InvalidAmount);
        }

        // Fetch stats
        let mut stats: EventStats = env
            .storage()
            .persistent()
            .get(&DataKey::EventStats(event_id))
            .unwrap_or(EventStats {
                recipient_count: 0,
                total_distributed: 0,
            });

        // Process each user
        let mut successful_claims = 0;
        for user in users.iter() {
            // Skip if already claimed
            if self.has_claimed(env, &user, event_id) {
                continue;
            }

            // Check caps
            if let Some(max_users) = airdrop_event.max_users {
                if stats.recipient_count >= max_users {
                    return Err(AirdropError::CapExceeded);
                }
            }
            if let Some(max_total) = airdrop_event.max_total_amount {
                if stats.total_distributed + airdrop_event.amount > max_total {
                    return Err(AirdropError::CapExceeded);
                }
            }

            // Check eligibility
            if self.check_eligibility(env, &user, event_id).is_err() {
                continue;
            }

            // Transfer tokens
            if self
                .transfer_tokens(
                    env,
                    &airdrop_event.token_address,
                    &user,
                    airdrop_event.amount,
                )
                .is_err()
            {
                continue;
            }

            // Update stats and mark claimed
            stats.recipient_count += 1;
            stats.total_distributed += airdrop_event.amount;
            self.mark_claimed(env, &user, event_id);
            successful_claims += 1;

            // Emit event
            env.events().publish(
                (
                    Symbol::new(env, "Claimed"),
                    event_id,
                    user.clone(),
                    airdrop_event.name.clone(),
                ),
                (
                    airdrop_event.token_address.clone(),
                    airdrop_event.amount,
                    current_time,
                ),
            );
        }

        // Save updated stats
        env.storage()
            .persistent()
            .set(&DataKey::EventStats(event_id), &stats);

        // Fail if no successful claims
        if successful_claims == 0 {
            return Err(AirdropError::UserNotEligible);
        }

        Ok(())
    }
}
