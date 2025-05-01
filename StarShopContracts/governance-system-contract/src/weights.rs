cat > StarShopContracts/governance-system-contract/src/weights.rs << 'EOF'
use soroban_sdk::{Address, Env, Map, Symbol, Vec, vec, contract};
use crate::types::{Error, WeightSnapshot, WEIGHT_PREFIX, DELEGATE_PREFIX, SNAPSHOT_PREFIX, TOKEN_KEY};

pub struct WeightCalculator;

impl WeightCalculator {
    // Initialize the weight calculator
    pub fn init(env: &Env) {
        // No specific initialization needed for now
    }
    
    // Set the token contract for weight calculation
    pub fn set_token(env: &Env, token: &Address) {
        env.storage().instance().set(TOKEN_KEY, token);
    }
    
    // Take a snapshot of token balances for a proposal
    pub fn take_snapshot(env: &Env, proposal_id: u32) -> Result<(), Error> {
        let snapshot = WeightSnapshot {
            proposal_id,
            snapshot_at: env.ledger().timestamp(),
        };
        
        let key = Self::get_snapshot_key(proposal_id);
        env.storage().instance().set(key, snapshot);
        
        // In a real implementation, we would query token balances here and store them
        // For now, we'll simulate this with a placeholder
        
        Ok(())
    }
    
    // Get the vote weight for a voter on a specific proposal
    pub fn get_weight(env: &Env, voter: &Address, proposal_id: u32) -> Result<i128, Error> {
        // Check if the voter has delegated their vote
        if let Some(delegatee) = Self::get_delegation(env, voter) {
            // If delegated, return 0 weight for the delegator
            return Ok(0);
        }
        
        // Get the base weight (token balance)
        let base_weight = Self::get_base_weight(env, voter);
        
        // Add any weight delegated to this voter for this proposal
        let delegated_weight = Self::get_delegated_weight(env, voter, proposal_id);
        
        // Apply max cap to prevent whale dominance
        let total_weight = base_weight + delegated_weight;
        let max_weight = Self::get_max_weight_cap(env);
        
        if total_weight > max_weight {
            Ok(max_weight)
        } else {
            Ok(total_weight)
        }
    }
    
    // Get the base voting weight for an address (from token balance)
    pub fn get_base_weight(env: &Env, voter: &Address) -> i128 {
        // In a real implementation, this would query the token contract
        // For a placeholder, we'll use a simple value
        100 // placeholder value
    }
    
    // Get weight delegated to this voter
    fn get_delegated_weight(env: &Env, delegatee: &Address, proposal_id: u32) -> i128 {
        let mut total = 0i128;
        
        // Get all delegators
        let delegators = Self::get_delegators(env, delegatee);
        
        // Sum up their weights
        for delegator in delegators.iter() {
            let weight = Self::get_base_weight(env, &delegator);
            total += weight;
        }
        
        total
    }
    
    // Delegate voting power
    pub fn delegate(env: &Env, delegator: &Address, delegatee: &Address) -> Result<(), Error> {
        // Can't delegate to yourself
        if delegator == delegatee {
            return Err(Error::SelfDelegationNotAllowed);
        }
        
        // Check for delegation loops
        if let Some(current_delegatee) = Self::get_delegation(env, delegatee) {
            if current_delegatee == *delegator {
                return Err(Error::InvalidDelegation);
            }
        }
        
        // Store the delegation
        let key = Self::get_delegator_key(delegator);
        env.storage().instance().set(key, delegatee);
        
        // Update delegators list
        Self::add_to_delegators_list(env, delegatee, delegator);
        
        Ok(())
    }
    
    // Remove delegation
    pub fn undelegate(env: &Env, delegator: &Address) -> Result<(), Error> {
        let key = Self::get_delegator_key(delegator);
        
        if let Some(delegatee) = env.storage().instance().get::<_, Address>(key.clone()) {
            // Remove from storage
            env.storage().instance().remove(key);
            
            // Remove from delegators list
            Self::remove_from_delegators_list(env, &delegatee, delegator);
        }
        
        Ok(())
    }
    
    // Get the current delegation for an address
    pub fn get_delegation(env: &Env, delegator: &Address) -> Option<Address> {
        let key = Self::get_delegator_key(delegator);
        env.storage().instance().get(key)
    }
    
    // Get all addresses that delegated to this address
    pub fn get_delegators(env: &Env, delegatee: &Address) -> Vec<Address> {
        let key = Self::get_delegatees_key(delegatee);
        env.storage().instance().get(key).unwrap_or_else(|| vec![env])
    }
    
    // Get max weight cap for any single voter
    fn get_max_weight_cap(env: &Env) -> i128 {
        // In a real implementation, this would be configurable
        // For now, we'll use a simple value
        10000 // placeholder value
    }
    
    // Helper methods for storage keys
    fn get_snapshot_key(proposal_id: u32) -> Symbol {
        Symbol::new(format!("{}_{}", SNAPSHOT_PREFIX, proposal_id))
    }
    
    fn get_delegator_key(delegator: &Address) -> Symbol {
        Symbol::new(format!("{}:{}", DELEGATE_PREFIX, delegator))
    }
    
    fn get_delegatees_key(delegatee: &Address) -> Symbol {
        Symbol::new(format!("{}_TO:{}", DELEGATE_PREFIX, delegatee))
    }
    
    // Helper methods for managing delegators list
    fn add_to_delegators_list(env: &Env, delegatee: &Address, delegator: &Address) {
        let key = Self::get_delegatees_key(delegatee);
        let mut list: Vec<Address> = env.storage().instance().get(key.clone()).unwrap_or_else(|| vec![env]);
        
        if !list.iter().any(|a| a == delegator) {
            list.push_back(delegator.clone());
            env.storage().instance().set(key, list);
        }
    }
    
    fn remove_from_delegators_list(env: &Env, delegatee: &Address, delegator: &Address) {
        let key = Self::get_delegatees_key(delegatee);
        let mut list: Vec<Address> = env.storage().instance().get(key.clone()).unwrap_or_else(|| vec![env]);
        
        let mut new_list = vec![env];
        for addr in list.iter() {
            if addr != delegator {
                new_list.push_back(addr.clone());
            }
        }
        
        env.storage().instance().set(key, new_list);
    }
}
