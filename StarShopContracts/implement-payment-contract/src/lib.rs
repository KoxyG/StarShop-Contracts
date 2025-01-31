#![no_std]
use soroban_sdk::{contract, contracterror, contractimpl, symbol_short, Address, BytesN, Env};

mod dispute;
mod refund;
#[cfg(test)]
mod test;
mod transaction;

pub use dispute::{DisputeContract, DisputeDecision, DisputeError};
pub use refund::{RefundContract, RefundError};
pub use transaction::{TransactionContract, TransactionError};

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum PaymentError {
    NotInitialized = 1,
    AlreadyInitialized = 2,
    UnauthorizedAccess = 3,
}

#[contract]
pub struct PaymentContract;

#[contractimpl]
impl PaymentContract {
    /// Initializes the contract with an admin address
    pub fn initialize(env: Env, admin: Address) -> Result<(), PaymentError> {
        // Verify contract isn't already initialized
        if env.storage().instance().has(&symbol_short!("admin")) {
            return Err(PaymentError::AlreadyInitialized);
        }

        admin.require_auth();
        env.storage()
            .instance()
            .set(&symbol_short!("admin"), &admin);

        // Emit initialization event
        env.events().publish((symbol_short!("init"),), (admin,));

        Ok(())
    }

    /// Upgrades the contract with new WASM code
    pub fn upgrade(env: Env, new_wasm_hash: BytesN<32>) -> Result<(), PaymentError> {
        let admin: Address = env
            .storage()
            .instance()
            .get(&symbol_short!("admin"))
            .ok_or(PaymentError::NotInitialized)?;

        admin.require_auth();
        env.deployer()
            .update_current_contract_wasm(new_wasm_hash.clone());

        // Emit upgrade event
        env.events()
            .publish((symbol_short!("upgrade"),), (admin, new_wasm_hash));

        Ok(())
    }

    /// Returns the current admin address
    pub fn get_admin(env: Env) -> Result<Address, PaymentError> {
        env.storage()
            .instance()
            .get(&symbol_short!("admin"))
            .ok_or(PaymentError::NotInitialized)
    }

    /// Transfers admin rights to a new address
    pub fn transfer_admin(env: Env, new_admin: Address) -> Result<(), PaymentError> {
        let current_admin: Address = env
            .storage()
            .instance()
            .get(&symbol_short!("admin"))
            .ok_or(PaymentError::NotInitialized)?;

        current_admin.require_auth();
        new_admin.require_auth();

        env.storage()
            .instance()
            .set(&symbol_short!("admin"), &new_admin);

        // Emit admin transfer event
        env.events()
            .publish((symbol_short!("adm_xfer"),), (current_admin, new_admin));

        Ok(())
    }
}
