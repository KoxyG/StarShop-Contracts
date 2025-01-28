use soroban_sdk::{symbol_short, Address, Env, Map, Vec};
use crate::types::Error;

pub struct VoteLimiter;

const DAILY_VOTE_LIMIT: usize = 10;
const MIN_ACCOUNT_AGE: u64 = 7 * 24 * 60 * 60; // 7 days in seconds

impl VoteLimiter {
    pub fn init(env: &Env) {
        let user_votes: Map<Address, Vec<u64>> = Map::new(env);
        env.storage().instance().set(&symbol_short!("user_votes"), &user_votes);
    }

    pub fn check_limits(env: &Env, voter: &Address) -> Result<(), Error> {
        let mut user_votes: Map<Address, Vec<u64>> = env.storage().instance().get(&symbol_short!("user_votes")).unwrap();
        let mut user_recent_votes = user_votes.get(voter.clone()).unwrap_or(Vec::new(env));
        
        let now = env.ledger().timestamp();

        // Check account age
        if let Some(created_at) = Self::get_account_creation_time(env, voter) {
            if now - created_at < MIN_ACCOUNT_AGE {
                return Err(Error::AccountTooNew);
            }
        }

        // Remove votes older than 24 hours
        let day_ago = now - 24 * 60 * 60;
        user_recent_votes.retain(|&timestamp| timestamp > day_ago);

        // Check daily limit
        if user_recent_votes.len() >= DAILY_VOTE_LIMIT {
            return Err(Error::DailyLimitReached);
        }

        // Record new vote timestamp
        user_recent_votes.push_back(now);
        user_votes.set(voter.clone(), user_recent_votes);
        env.storage().instance().set(&symbol_short!("user_votes"), &user_votes);

        Ok(())
    }

    fn get_account_creation_time(_env: &Env, _address: &Address) -> Option<u64> {
        // Once in main net this would query the Stellar network instead
        Some(0)
    }
}