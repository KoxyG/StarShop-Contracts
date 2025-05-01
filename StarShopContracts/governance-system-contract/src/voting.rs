cat > StarShopContracts/governance-system-contract/src/voting.rs << 'EOF'
use soroban_sdk::{Address, Env, Map, Symbol, Vec, vec};
use crate::types::{Error, Vote, VotingConfig, VOTE_PREFIX};

pub struct VotingSystem;

impl VotingSystem {
    // Initialize the voting system
    pub fn init(env: &Env) {
        // No specific initialization needed for now
    }
    
    // Cast a vote on a proposal
    pub fn cast_vote(
        env: &Env,
        proposal_id: u32,
        voter: &Address,
        support: bool,
        weight: i128,
    ) -> Result<(), Error> {
        // Check if the voter has already voted
        let key = Self::get_vote_key(proposal_id, voter);
        if env.storage().instance().has(key.clone()) {
            return Err(Error::AlreadyVoted);
        }
        
        // Create and store the vote
        let vote = Vote {
            voter: voter.clone(),
            support,
            weight,
            timestamp: env.ledger().timestamp(),
        };
        
        env.storage().instance().set(key, vote);
        
        // Update vote tracking
        Self::update_vote_totals(env, proposal_id, support, weight);
        
        Ok(())
    }
    
    // Update vote totals when a new vote is cast
    fn update_vote_totals(env: &Env, proposal_id: u32, support: bool, weight: i128) {
        let key_for = Self::get_vote_totals_key(proposal_id, true);
        let key_against = Self::get_vote_totals_key(proposal_id, false);
        let key_total = Self::get_vote_total_key(proposal_id);
        
        // Get current totals
        let mut for_votes: i128 = env.storage().instance().get(key_for.clone()).unwrap_or(0);
        let mut against_votes: i128 = env.storage().instance().get(key_against.clone()).unwrap_or(0);
        let mut total_votes: i128 = env.storage().instance().get(key_total.clone()).unwrap_or(0);
        
        // Update totals
        if support {
            for_votes += weight;
        } else {
            against_votes += weight;
        }
        total_votes += weight;
        
        // Store updated totals
        env.storage().instance().set(key_for, for_votes);
        env.storage().instance().set(key_against, against_votes);
        env.storage().instance().set(key_total, total_votes);
        
        // Also update voter count
        let key_voter_count = Self::get_voter_count_key(proposal_id);
        let mut voter_count: u32 = env.storage().instance().get(key_voter_count.clone()).unwrap_or(0);
        voter_count += 1;
        env.storage().instance().set(key_voter_count, voter_count);
    }
    
    // Check if voting has ended for a proposal
    pub fn check_voting_ended(env: &Env, proposal_id: u32, config: &VotingConfig) -> Result<bool, Error> {
        // Get the proposal activation time from the proposals module
        let activation_time = Self::get_proposal_activation_time(env, proposal_id)?;
        
        // If we've passed the voting duration, voting has ended
        let current_time = env.ledger().timestamp();
        if current_time >= activation_time + config.duration {
            return Ok(true);
        }
        
        // Check if we've reached quorum early
        let total_votes = Self::get_total_votes(env, proposal_id);
        let total_voting_power = Self::get_total_voting_power(env, proposal_id);
        
        if total_votes * 10000 / total_voting_power >= config.quorum {
            // Check if there's a clear winner already
            let for_votes = Self::get_for_votes(env, proposal_id);
            let against_votes = Self::get_against_votes(env, proposal_id);
            
            if for_votes * 10000 / total_votes >= config.threshold {
                return Ok(true);
            }
            
            if against_votes * 10000 / total_votes > (10000 - config.threshold) {
                return Ok(true);
            }
        }
        
        Ok(false)
    }
    
    // Tally votes for a proposal to determine if it passed
    pub fn tally_votes(env: &Env, proposal_id: u32, config: &VotingConfig) -> Result<bool, Error> {
        let for_votes = Self::get_for_votes(env, proposal_id);
        let total_votes = Self::get_total_votes(env, proposal_id);
        let total_voting_power = Self::get_total_voting_power(env, proposal_id);
        
        // Check quorum
        if total_votes * 10000 / total_voting_power < config.quorum {
            return Ok(false); // Failed to reach quorum
        }
        
        // Check threshold
        if for_votes * 10000 / total_votes >= config.threshold {
            return Ok(true); // Passed
        }
        
        Ok(false) // Failed to reach threshold
    }
    
    // Get all votes for a proposal
    pub fn get_votes(env: &Env, proposal_id: u32) -> Vec<Vote> {
        let prefix = format!("{}_{}:", VOTE_PREFIX, proposal_id);
        let mut votes = vec![env];
        
        // This would be a simplified version - in production, we'd need pagination
        let keys = env.storage().instance().keys();
        for key in keys.iter() {
            let key_str = key.to_string();
            if key_str.starts_with(&prefix) {
                if let Some(vote) = env.storage().instance().get::<_, Vote>(key.clone()) {
                    votes.push_back(vote);
                }
            }
        }
        
        votes
    }
    
    // Get count of voters
    pub fn get_voter_count(env: &Env, proposal_id: u32) -> u32 {
        let key = Self::get_voter_count_key(proposal_id);
        env.storage().instance().get(key).unwrap_or(0)
    }
    
    // Get total 'for' votes
    pub fn get_for_votes(env: &Env, proposal_id: u32) -> i128 {
        let key = Self::get_vote_totals_key(proposal_id, true);
        env.storage().instance().get(key).unwrap_or(0)
    }
    
    // Get total 'against' votes
    pub fn get_against_votes(env: &Env, proposal_id: u32) -> i128 {
        let key = Self::get_vote_totals_key(proposal_id, false);
        env.storage().instance().get(key).unwrap_or(0)
    }
    
    // Get total votes
    pub fn get_total_votes(env: &Env, proposal_id: u32) -> i128 {
        let key = Self::get_vote_total_key(proposal_id);
        env.storage().instance().get(key).unwrap_or(0)
    }
    
    // Get total voting power (would be populated by the token contract)
    pub fn get_total_voting_power(env: &Env, proposal_id: u32) -> i128 {
        let key = Symbol::new(format!("TOTAL_VOTING_POWER_{}", proposal_id));
        env.storage().instance().get(key).unwrap_or(10000) // Default to 10000 if not set
    }
    
    // Helper to get activation time from proposal
    fn get_proposal_activation_time(env: &Env, proposal_id: u32) -> Result<u64, Error> {
        // In a real implementation, we would query the proposal's activation time
        // For now, we'll just use the current time minus a day as a placeholder
        let current_time = env.ledger().timestamp();
        Ok(current_time - 86400) // Placeholder, would be replaced with actual query
    }
    
    // Helper methods for storage keys
    fn get_vote_key(proposal_id: u32, voter: &Address) -> Symbol {
        Symbol::new(format!("{}_{}:{}", VOTE_PREFIX, proposal_id, voter))
    }
    
    fn get_vote_totals_key(proposal_id: u32, support: bool) -> Symbol {
        if support {
            Symbol::new(format!("{}_{}:FOR", VOTE_PREFIX, proposal_id))
        } else {
            Symbol::new(format!("{}_{}:AGAINST", VOTE_PREFIX, proposal_id))
        }
    }
    
    fn get_vote_total_key(proposal_id: u32) -> Symbol {
        Symbol::new(format!("{}_{}:TOTAL", VOTE_PREFIX, proposal_id))
    }
    
    fn get_voter_count_key(proposal_id: u32) -> Symbol {
        Symbol::new(format!("{}_{}:COUNT", VOTE_PREFIX, proposal_id))
    }
}
