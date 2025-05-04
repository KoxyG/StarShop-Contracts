use soroban_sdk::{Address, Env, Symbol, Vec, vec, symbol_short};
use crate::types::{Error, WeightSnapshot, TOKEN_KEY};

pub struct WeightCalculator;

impl WeightCalculator {
    pub fn init(env: &Env, token: &Address) {
        env.storage().instance().set(&TOKEN_KEY, token);
    }

    pub fn take_snapshot(env: &Env, proposal_id: u32) -> Result<(), Error> {
        let snapshot = WeightSnapshot {
            proposal_id,
            snapshot_at: env.ledger().timestamp(),
        };
        let key = Self::get_snapshot_key(env, proposal_id);
        env.storage().instance().set(&key, &snapshot);
        // Placeholder: Store token balances
        env.storage().instance().set(&Symbol::new(&env, &format!("TOTAL_VOTING_POWER_{}", proposal_id)), &10000i128);
        Ok(())
    }

    pub fn get_weight(env: &Env, voter: &Address, proposal_id: u32) -> Result<i128, Error> {
        if let Some(delegatee) = Self::get_delegation(env, voter) {
            return Ok(0);
        }
        let base_weight = Self::get_base_weight(env, voter);
        let delegated_weight = Self::get_delegated_weight(env, voter, proposal_id);
        let total_weight = base_weight + delegated_weight;
        let max_weight = 10000i128; // Configurable cap
        Ok(total_weight.min(max_weight))
    }

    pub fn get_base_weight(env: &Env, voter: &Address) -> i128 {
        // Placeholder: Query token balance
        1000 // Simulate balance
    }

    fn get_delegated_weight(env: &Env, delegatee: &Address, _proposal_id: u32) -> i128 {
        let delegators = Self::get_delegators(env, delegatee);
        delegators.iter().map(|delegator| Self::get_base_weight(env, &delegator)).sum()
    }

    pub fn delegate(env: &Env, delegator: &Address, delegatee: &Address) -> Result<(), Error> {
        if delegator == delegatee {
            return Err(Error::SelfDelegationNotAllowed);
        }
        if let Some(current_delegatee) = Self::get_delegation(env, delegatee) {
            if current_delegatee == *delegator {
                return Err(Error::InvalidDelegation);
            }
        }
        let key = Self::get_delegator_key(env, delegator);
        env.storage().instance().set(&key, delegatee);
        Self::add_to_delegators_list(env, delegatee, delegator);
        env.events().publish((symbol_short!("vote"), symbol_short!("delegated")), (delegator, delegatee));
        Ok(())
    }

    pub fn get_delegation(env: &Env, delegator: &Address) -> Option<Address> {
        let key = Self::get_delegator_key(env, delegator);
        env.storage().instance().get(&key)
    }

    pub fn get_delegators(env: &Env, delegatee: &Address) -> Vec<Address> {
        let key = Self::get_delegatees_key(env, delegatee);
        env.storage().instance().get(&key).unwrap_or_else(|| vec![env])
    }

    fn get_snapshot_key(env: &Env, proposal_id: u32) -> Symbol {
        Symbol::new(&env, &format!("SNAP_{}", proposal_id))
    }

    fn get_delegator_key(env: &Env, delegator: &Address) -> Symbol {
        Symbol::new(&env, &format!("DELG:{:?}", delegator))
    }

    fn get_delegatees_key(env: &Env, delegatee: &Address) -> Symbol {
        Symbol::new(&env, &format!("DELG_TO:{:?}", delegatee))
    }

    fn add_to_delegators_list(env: &Env, delegatee: &Address, delegator: &Address) {
        let key = Self::get_delegatees_key(env, delegatee);
        let mut list: Vec<Address> = env.storage().instance().get(&key).unwrap_or_else(|| vec![env]);
        if !list.iter().any(|a| a == *delegator) {
            list.push_back(delegator.clone());
            env.storage().instance().set(&key, &list);
        }
    }
}