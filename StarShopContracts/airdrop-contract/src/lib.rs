#![no_std]
use core::ops::Add;

use soroban_sdk::{Address, Env, Map, Symbol, Vec, contract, contractimpl};

pub mod distribution;
pub mod eligibility;
pub mod tracking;
pub mod types;

use distribution::DistributionManager;
use eligibility::EligibilityManager;
use tracking::AirdropManager;
use types::{AirdropError, AirdropEvent, DataKey};

pub trait AirdropContractTrait {
    fn initialize(env: Env, admin: Address) -> Result<(), AirdropError>;
    fn trigger_airdrop(
        env: Env,
        conditions: Map<Symbol, u64>,
        amount: u64,
        token_address: Address,
    ) -> Result<(), AirdropError>;
    fn claim_airdrop(env: Env, user: Address, event_id: u64) -> Result<(), AirdropError>;
    fn distribute_all(env: Env, event_id: u64, users: Vec<Address>) -> Result<(), AirdropError>;
}

#[contract]
pub struct AirdropContract;

#[contractimpl]
impl AirdropContractTrait for AirdropContract {
    fn initialize(env: Env, admin: Address) -> Result<(), AirdropError> {
        if env.storage().persistent().has(&DataKey::Admin) {
            return Err(AirdropError::AlreadyInitialized);
        }
        admin.require_auth();
        env.storage().persistent().set(&DataKey::Admin, &admin);
        env.storage().persistent().set(&DataKey::EventId, &0u64);
        Ok(())
    }

    fn trigger_airdrop(
        env: Env,
        conditions: Map<Symbol, u64>,
        amount: u64,
        token_address: Address,
    ) -> Result<(), AirdropError> {
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .ok_or(AirdropError::Unauthorized)?;
        admin.require_auth();

        if amount <= 0 {
            return Err(AirdropError::InvalidAmount);
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
            conditions,
            amount,
            token_address,
        };
        env.storage()
            .persistent()
            .set(&DataKey::AirdropEvent(new_event_id), &airdrop_event);

        Ok(())
    }

    fn claim_airdrop(env: Env, user: Address, event_id: u64) -> Result<(), AirdropError> {
        user.require_auth();

        // Check eligibility
        EligibilityManager::new(&env).check_eligibility(&user, event_id)?;

        // Distribute tokens
        DistributionManager::new(&env).distribute_tokens(&user, event_id)?;

        Ok(())
    }

    fn distribute_all(env: Env, event_id: u64, users: Vec<Address>) -> Result<(), AirdropError> {
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .ok_or(AirdropError::Unauthorized)?;
        admin.require_auth();

        let distribution_manager = DistributionManager::new(&env);
        let eligibility_manager = EligibilityManager::new(&env);

        for user in users.iter() {
            // Skip if user is not eligible or has already claimed
            if eligibility_manager
                .check_eligibility(&user, event_id)
                .is_ok()
            {
                let _ = distribution_manager.distribute_tokens(&user, event_id);
            }
        }

        Ok(())
    }
}
