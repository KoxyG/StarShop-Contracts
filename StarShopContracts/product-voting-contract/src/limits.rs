use soroban_sdk::{symbol_short, Address, Env, Map, Vec};
use crate::types::Error;

pub struct VoteLimiter;

const DAILY_VOTE_LIMIT: u32 = 10;
const MIN_ACCOUNT_AGE: u64 = 7 * 24 * 60 * 60; // 7 days in seconds

impl VoteLimiter {
    pub fn init(env: &Env) {
        let usr_votes: Map<Address, Vec<u64>> = Map::new(env);
        env.storage().instance().set(&symbol_short!("usr_votes"), &usr_votes);
    }

    pub fn check_limits(env: &Env, voter: &Address) -> Result<(), Error> {
        let mut usr_votes: Map<Address, Vec<u64>> = env.storage().instance().get(&symbol_short!("usr_votes")).unwrap();
        let mut user_recent_votes = usr_votes.get(voter.clone()).unwrap_or(Vec::new(env));
        
        let now = env.ledger().timestamp();

        // Check account age
        if let Some(created_at) = Self::get_account_creation_time(env, voter) {
            if now - created_at < MIN_ACCOUNT_AGE {
                return Err(Error::AccountTooNew);
            }
        }

        // Remove votes older than 24 hours using manual filtering
        let day_ago = now - 24 * 60 * 60;
        let mut filtered_votes = Vec::new(env);
        for i in 0..user_recent_votes.len() {
            let timestamp = user_recent_votes.get(i).unwrap();
            if timestamp > day_ago {
                filtered_votes.push_back(timestamp);
            }
        }
        user_recent_votes = filtered_votes;

        // Check daily limit
        if user_recent_votes.len() >= DAILY_VOTE_LIMIT as u32 {
            return Err(Error::DailyLimitReached);
        }

        // Record new vote timestamp
        user_recent_votes.push_back(now);
        usr_votes.set(voter.clone(), user_recent_votes);
        env.storage().instance().set(&symbol_short!("usr_votes"), &usr_votes);

        Ok(())
    }

    fn get_account_creation_time(_env: &Env, _address: &Address) -> Option<u64> {
        // Once in main net this would query the Stellar network instead
        Some(0)
    }
}