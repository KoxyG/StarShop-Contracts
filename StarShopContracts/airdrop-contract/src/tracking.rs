use crate::types::{AirdropError, DataKey};
use soroban_sdk::{Address, Env, Symbol};

impl super::AirdropContract {
    /// Mark that a user has claimed an airdrop event.
    pub fn mark_claimed(&self, env: &Env, user: &Address, event_id: u64) {
        if !self.has_claimed(env, user, event_id) {
            env.storage()
                .persistent()
                .set(&DataKey::Claimed(event_id, user.clone()), &true);
            env.events().publish(
                (Symbol::new(env, "ClaimMarked"), event_id, user.clone()),
                true,
            );
        }
    }

    /// Check if a user has claimed an airdrop event.
    pub fn has_claimed(&self, env: &Env, user: &Address, event_id: u64) -> bool {
        env.storage()
            .persistent()
            .get(&DataKey::Claimed(event_id, user.clone()))
            .unwrap_or(false)
    }

    /// Internal: Mark an airdrop event as finalized (admin-only).
    pub fn internal_finalize_event(
        &self,
        env: &Env,
        admin: &Address,
        event_id: u64,
    ) -> Result<(), AirdropError> {
        admin.require_auth();

        if !env
            .storage()
            .persistent()
            .has(&DataKey::AirdropEvent(event_id))
        {
            return Err(AirdropError::AirdropNotFound);
        }

        if !self.internal_is_event_finalized(env, event_id) {
            env.storage()
                .persistent()
                .set(&DataKey::EventStatus(event_id), &true);
            env.events().publish(
                (Symbol::new(env, "EventFinalized"), event_id, admin.clone()),
                true,
            );
        }

        Ok(())
    }

    /// Internal: Check if an airdrop event is finalized.
    pub fn internal_is_event_finalized(&self, env: &Env, event_id: u64) -> bool {
        env.storage()
            .persistent()
            .get(&DataKey::EventStatus(event_id))
            .unwrap_or(false)
    }
}
