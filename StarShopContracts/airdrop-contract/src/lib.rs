#![no_std]
use soroban_sdk::{Address, Bytes, Env, Map, Symbol, Vec, contract, contractimpl};

mod distribution;
mod eligibility;
mod external;
mod test;
mod tracking;
mod types;

use types::{AirdropError, AirdropEvent, DataKey, EventStats};

#[contract]
pub struct AirdropContract;

#[contractimpl]
impl AirdropContract {
    /// Initialize the contract with an admin and optional provider registry.
    pub fn initialize(
        env: Env,
        admin: Address,
        initial_providers: Option<Map<Symbol, Address>>,
    ) -> Result<(), AirdropError> {
        if env.storage().persistent().has(&DataKey::Admin) {
            return Err(AirdropError::AlreadyInitialized);
        }
        admin.require_auth();
        env.storage().persistent().set(&DataKey::Admin, &admin);
        env.storage().persistent().set(&DataKey::EventId, &0u64);

        if let Some(providers) = initial_providers {
            for (metric, provider) in providers.iter() {
                // Ensure metric is not empty
                if metric == Symbol::new(&env, "") {
                    return Err(AirdropError::InvalidEventConfig);
                }
                // Provider address validity is checked at runtime in check_eligibility
                env.storage()
                    .persistent()
                    .set(&DataKey::ProviderRegistry(metric), &provider);
            }
        }

        Ok(())
    }

    /// Create a new airdrop event.
    pub fn trigger_airdrop(
        env: Env,
        admin: Address,
        name: Symbol,
        description: Bytes,
        conditions: Map<Symbol, u64>,
        amount: u64,
        token_address: Address,
        start_time: u64,
        end_time: u64,
        max_users: Option<u64>,
        max_total_amount: Option<u64>,
    ) -> Result<u64, AirdropError> {
        admin.require_auth();

        // Validate event configuration
        if name == Symbol::new(&env, "") || conditions.len() == 0 || amount == 0 {
            return Err(AirdropError::InvalidEventConfig);
        }
        let current_time = env.ledger().timestamp();
        if start_time < current_time || end_time <= start_time {
            return Err(AirdropError::InvalidEventConfig);
        }
        for (metric, value) in conditions.iter() {
            if metric == Symbol::new(&env, "") || value == 0 {
                return Err(AirdropError::InvalidEventConfig);
            }
        }

        let event_id: u64 = env
            .storage()
            .persistent()
            .get(&DataKey::EventId)
            .unwrap_or(0);
        let new_event_id = event_id + 1;
        env.storage()
            .persistent()
            .set(&DataKey::EventId, &new_event_id);

        let airdrop_event = AirdropEvent {
            name,
            description,
            conditions,
            amount,
            token_address,
            start_time,
            end_time,
            max_users,
            max_total_amount,
            is_active: true,
        };
        env.storage()
            .persistent()
            .set(&DataKey::AirdropEvent(new_event_id), &airdrop_event);

        env.storage().persistent().set(
            &DataKey::EventStats(new_event_id),
            &EventStats {
                recipient_count: 0,
                total_distributed: 0,
            },
        );

        env.events().publish(
            (Symbol::new(&env, "AirdropTriggered"), new_event_id, admin),
            (current_time, amount),
        );

        Ok(new_event_id)
    }

    /// User claims tokens for an airdrop event.
    pub fn claim_airdrop(env: Env, user: Address, event_id: u64) -> Result<(), AirdropError> {
        user.require_auth();
        Self::claim_tokens(&AirdropContract, &env, &user, event_id)
    }

    /// Admin triggers batch distribution.
    pub fn distribute_all(
        env: Env,
        admin: Address,
        event_id: u64,
        users: Vec<Address>,
    ) -> Result<(), AirdropError> {
        admin.require_auth();
        Self::distribute_batch(&AirdropContract, &env, &admin, event_id, users)
    }

    /// Register a metric provider.
    pub fn register_provider(
        env: Env,
        admin: Address,
        metric: Symbol,
        provider: Address,
    ) -> Result<(), AirdropError> {
        admin.require_auth();

        if metric == Symbol::new(&env, "") {
            return Err(AirdropError::InvalidEventConfig);
        }
        env.storage()
            .persistent()
            .set(&DataKey::ProviderRegistry(metric.clone()), &provider);
        env.events().publish(
            (Symbol::new(&env, "ProviderRegistered"), metric, admin),
            provider,
        );
        Ok(())
    }

    /// Update a metric provider.
    pub fn update_provider(
        env: Env,
        admin: Address,
        metric: Symbol,
        new_provider: Address,
    ) -> Result<(), AirdropError> {
        admin.require_auth();

        if !env
            .storage()
            .persistent()
            .has(&DataKey::ProviderRegistry(metric.clone()))
        {
            return Err(AirdropError::ProviderNotConfigured);
        }
        if metric == Symbol::new(&env, "") {
            return Err(AirdropError::InvalidEventConfig);
        }
        env.storage()
            .persistent()
            .set(&DataKey::ProviderRegistry(metric.clone()), &new_provider);
        env.events().publish(
            (Symbol::new(&env, "ProviderUpdated"), metric, admin),
            new_provider,
        );
        Ok(())
    }

    /// Remove a metric provider.
    pub fn remove_provider(env: Env, admin: Address, metric: Symbol) -> Result<(), AirdropError> {
        admin.require_auth();

        if !env
            .storage()
            .persistent()
            .has(&DataKey::ProviderRegistry(metric.clone()))
        {
            return Err(AirdropError::ProviderNotConfigured);
        }
        env.storage()
            .persistent()
            .remove(&DataKey::ProviderRegistry(metric.clone()));
        env.events()
            .publish((Symbol::new(&env, "ProviderRemoved"), metric, admin), true);
        Ok(())
    }

    /// Pause an airdrop event.
    pub fn pause_event(env: Env, admin: Address, event_id: u64) -> Result<(), AirdropError> {
        admin.require_auth();

        let mut event: AirdropEvent = env
            .storage()
            .persistent()
            .get(&DataKey::AirdropEvent(event_id))
            .ok_or(AirdropError::AirdropNotFound)?;
        if !event.is_active {
            return Err(AirdropError::EventInactive);
        }
        event.is_active = false;
        env.storage()
            .persistent()
            .set(&DataKey::AirdropEvent(event_id), &event);
        env.events()
            .publish((Symbol::new(&env, "EventPaused"), event_id, admin), true);
        Ok(())
    }

    /// Resume a paused airdrop event.
    pub fn resume_event(env: Env, admin: Address, event_id: u64) -> Result<(), AirdropError> {
        admin.require_auth();

        let mut event: AirdropEvent = env
            .storage()
            .persistent()
            .get(&DataKey::AirdropEvent(event_id))
            .ok_or(AirdropError::AirdropNotFound)?;
        if event.is_active {
            return Err(AirdropError::InvalidEventConfig);
        }
        event.is_active = true;
        env.storage()
            .persistent()
            .set(&DataKey::AirdropEvent(event_id), &event);
        env.events()
            .publish((Symbol::new(&env, "EventResumed"), event_id, admin), true);
        Ok(())
    }

    /// Finalize an airdrop event.
    pub fn finalize_event(env: Env, admin: Address, event_id: u64) -> Result<(), AirdropError> {
        Self::internal_finalize_event(&AirdropContract, &env, &admin, event_id)
    }

    /// Update the admin address.
    pub fn set_admin(
        env: Env,
        current_admin: Address,
        new_admin: Address,
    ) -> Result<(), AirdropError> {
        current_admin.require_auth();

        new_admin.require_auth();
        env.storage().persistent().set(&DataKey::Admin, &new_admin);
        env.events().publish(
            (Symbol::new(&env, "AdminUpdated"), current_admin),
            new_admin,
        );
        Ok(())
    }

    /// Query an airdrop event.
    pub fn get_event(env: Env, event_id: u64) -> Result<AirdropEvent, AirdropError> {
        env.storage()
            .persistent()
            .get(&DataKey::AirdropEvent(event_id))
            .ok_or(AirdropError::AirdropNotFound)
    }

    /// Query event statistics.
    pub fn get_event_stats(env: Env, event_id: u64) -> Result<EventStats, AirdropError> {
        env.storage()
            .persistent()
            .get(&DataKey::EventStats(event_id))
            .ok_or(AirdropError::AirdropNotFound)
    }

    /// Query claimed users for an event.
    pub fn list_claimed_users(
        env: Env,
        event_id: u64,
        _max_results: u32,
    ) -> Result<Vec<Address>, AirdropError> {
        if !env
            .storage()
            .persistent()
            .has(&DataKey::AirdropEvent(event_id))
        {
            return Err(AirdropError::AirdropNotFound);
        }
        // Placeholder: Assumes off-chain indexer for production.
        Ok(Vec::new(&env))
    }

    /// Query a provider address for a metric.
    pub fn get_provider(env: Env, metric: Symbol) -> Result<Address, AirdropError> {
        env.storage()
            .persistent()
            .get(&DataKey::ProviderRegistry(metric))
            .ok_or(AirdropError::ProviderNotConfigured)
    }

    /// Check if an address is the admin.
    pub fn is_admin(env: Env, address: Address) -> bool {
        env.storage()
            .persistent()
            .get(&DataKey::Admin)
            .map(|admin: Address| admin == address)
            .unwrap_or(false)
    }
}
