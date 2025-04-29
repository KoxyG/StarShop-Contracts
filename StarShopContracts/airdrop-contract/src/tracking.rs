use crate::types::*;
use soroban_sdk::{Address, Env, Symbol};

/// Mark that a user has claimed an airdrop event.
pub fn mark_claimed(env: &Env, user: &Address, event_id: u64) {
    if has_claimed(&env, &user, event_id) {
        env.storage()
            .persistent()
            .set(&DataKey::Claimed(event_id, user.clone()), &true);
        env.events().publish(
            (Symbol::new(&env, "ClaimMarked"), event_id, user.clone()),
            true,
        );
    }
}

/// Check if a user has claimed an airdrop event.
pub fn has_claimed(env: &Env, user: &Address, event_id: u64) -> bool {
    env.storage()
        .persistent()
        .get(&DataKey::Claimed(event_id, user.clone()))
        .unwrap_or(false)
}

/// Internal: Mark an airdrop event as finalized (admin-only).
pub fn internal_finalize_event(
    env: Env,
    admin: Address,
    event_id: u64,
) -> Result<(), AirdropError> {
    admin.require_auth();

    // Fetch the event
    let mut airdrop_event: AirdropEvent = env
        .storage()
        .persistent()
        .get(&DataKey::AirdropEvent(event_id))
        .ok_or(AirdropError::AirdropNotFound)?;

    // Check if already finalized
    if !airdrop_event.is_active {
        // Already finalized, no action needed
        return Ok(());
    }

    // Mark as finalized by setting is_active to false
    airdrop_event.is_active = false;
    env.storage()
        .persistent()
        .set(&DataKey::AirdropEvent(event_id), &airdrop_event);

    // Emit event
    env.events().publish(
        (Symbol::new(&env, "EventFinalized"), event_id, admin.clone()),
        true,
    );

    Ok(())
}

/// Internal: Check if an airdrop event is finalized.
pub fn internal_is_event_finalized(env: Env, event_id: u64) -> bool {
    env.storage()
        .persistent()
        .get(&DataKey::AirdropEvent(event_id))
        .map(|event: AirdropEvent| !event.is_active)
        .unwrap_or(true) // If event doesn't exist, consider it finalized
}
