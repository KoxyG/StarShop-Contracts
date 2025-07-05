use crate::{
    datatypes::{DataKey, PaymentEscrowError},
    interface::ArbitratorInterface,
    PaymentEscrowContract, PaymentEscrowContractClient, PaymentEscrowContractArgs
};
use soroban_sdk::{contractimpl, symbol_short, Address, Env, Vec};


#[contractimpl]
impl ArbitratorInterface for PaymentEscrowContract {
    fn add_arbitrator(env: Env, arbitrator: Address) -> Result<(), PaymentEscrowError> {
        // Authentication - admin must authorize this transaction
        arbitrator.require_auth();

        // Get the arbitrators from storage
        let mut arbitrators: Vec<Address> = env
            .storage()
            .persistent()
            .get(&DataKey::Arbitrator)
            .ok_or(PaymentEscrowError::NotFound)?;

        // Check if the arbitrator is already in the list
        if arbitrators.contains(&arbitrator) {
            return Err(PaymentEscrowError::NotArbitrator);
        }

        // Add the arbitrator to the list
        arbitrators.push_back(arbitrator.clone());
        env.storage()
            .persistent()
            .set(&DataKey::Arbitrator, &arbitrators);

        // Publish event
        env.events().publish((symbol_short!("new_arb"), arbitrator.clone()), arbitrator.clone());

        Ok(())
    }   

    fn remove_arbitrator(env: Env, arbitrator: Address) -> Result<(), PaymentEscrowError> {
        // Authentication - admin must authorize this transaction
        arbitrator.require_auth();

        // Get the arbitrators from storage
        let arbitrators: Vec<Address> = env
            .storage()
            .persistent()
            .get(&DataKey::Arbitrator)
            .ok_or(PaymentEscrowError::NotFound)?;

        // Check if the arbitrator is in the list
        if !arbitrators.contains(&arbitrator) {
            return Err(PaymentEscrowError::NotArbitrator);
        }

        // Remove the arbitrator from the list
        let mut new_arbitrators = Vec::new(&env);
        for a in arbitrators.iter() {
            if a != arbitrator {
                new_arbitrators.push_back(a);
            }
        }
        env.storage()
            .persistent()
            .set(&DataKey::Arbitrator, &new_arbitrators);

        Ok(())
    }

    fn get_arbitrators(env: Env) -> Result<Vec<Address>, PaymentEscrowError> {
        // Get the arbitrators from storage
        let arbitrators: Vec<Address> = env
            .storage()
            .persistent()
            .get(&DataKey::Arbitrator)
            .ok_or(PaymentEscrowError::NotFound)?;

        Ok(arbitrators)
    }

    fn transfer_arbitrator_rights(env: Env, old_arbitrator: Address, new_arbitrator: Address) -> Result<(), PaymentEscrowError> {
        // Authentication - new arbitrator must authorize this transaction
        old_arbitrator.require_auth();

        // Get the arbitrators from storage
        let arbitrators: Vec<Address> = env
            .storage()
            .persistent()
            .get(&DataKey::Arbitrator)
            .ok_or(PaymentEscrowError::UnauthorizedAccess)?;

        // Check if caller is in the arbitrator list
        if !arbitrators.contains(&old_arbitrator) {
            return Err(PaymentEscrowError::NotArbitrator);
        }

        // Check if new arbitrator is already in the list
        if arbitrators.contains(&new_arbitrator) {
            return Err(PaymentEscrowError::ArbitratorAlreadyExists);
        }

        // Create new list: keep all existing arbitrators except the caller, then add new arbitrator
        let mut new_arbitrators = Vec::new(&env);
        for a in arbitrators.iter() {
            if a != old_arbitrator {
                new_arbitrators.push_back(a.clone());
            }
        }
        new_arbitrators.push_back(new_arbitrator.clone());

        // Update storage
        env.storage()
            .persistent()
            .set(&DataKey::Arbitrator, &new_arbitrators);

        // Publish event
        env.events().publish(
            (symbol_short!("xfer_arb"), old_arbitrator.clone(), new_arbitrator.clone()), 
            new_arbitrator
        );

        Ok(())
    }
    
}