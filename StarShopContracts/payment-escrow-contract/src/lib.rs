#![no_std]
use soroban_sdk::{contract, contractimpl, Env, Address, Vec, BytesN};
use crate::datatypes::{DataKey, PaymentEscrowError};


#[contract]
pub struct PaymentEscrowContract;

#[contractimpl]
impl PaymentEscrowContract {
    pub fn init(env: Env, arbitrator: Address) -> Result<(), PaymentEscrowError> {
        // Check if contract is already initialized
        if env.storage().persistent().has(&DataKey::Arbitrator) {
            return Err(PaymentEscrowError::AlreadyInitialized);
        }

        let mut arbitrators = Vec::new(&env);
        arbitrators.push_back(arbitrator);
        env.storage().persistent().set(&DataKey::Arbitrator, &arbitrators);

        Ok(())
    }

    pub fn version() -> u32 {
        1
    }

    pub fn upgrade(e: Env, new_wasm_hash: BytesN<32>) {
        let arbitrators: Vec<Address> = e.storage().persistent().get(&DataKey::Arbitrator).unwrap();
        arbitrators.iter().for_each(|a| a.require_auth());

        e.deployer().update_current_contract_wasm(new_wasm_hash);
    }
}

pub use implementations::*;

// Declare modules
mod datatypes;
mod interface;
mod implementations;
// mod token;
mod test;