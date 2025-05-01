cat > StarShopContracts/governance-system-contract/src/proposals.rs << 'EOF'
use soroban_sdk::{Address, Env, Map, Symbol, Vec, vec};
use crate::types::{Error, Proposal, ProposalStatus, ProposalType, Action, VotingConfig, ProposalRequirements, ADMIN_KEY, PROPOSAL_COUNTER_KEY, PROPOSAL_PREFIX, PROPOSAL_IDS_KEY, PROPOSAL_STATUS_PREFIX, REQUIREMENTS_KEY};

pub struct ProposalManager;

impl ProposalManager {
    // Initialize the proposal system
    pub fn init(env: &Env, admin: &Address) {
        // Check if already initialized
        if env.storage().instance().has(ADMIN_KEY) {
            panic!("already initialized");
        }

        // Set the admin address
        env.storage().instance().set(ADMIN_KEY, admin);
        
        // Initialize the proposal counter
        env.storage().instance().set(PROPOSAL_COUNTER_KEY, 0u32);
        
        // Set default proposal requirements
        let requirements = ProposalRequirements {
            cooldown_period: 86400, // 24 hours in seconds
            required_stake: 100,    // 100 tokens required to stake
            proposal_limit: 5,      // Max 5 active proposals per address
        };
        
        env.storage().instance().set(REQUIREMENTS_KEY, requirements);
        
        // Initialize empty proposal lists by status
        for status in 0..6 {
            let status_key = Self::get_status_key(ProposalStatus::from_u32(status));
            env.storage().instance().set(status_key, vec![env; 0u32]);
        }
    }
    
    // Check if caller is admin
    pub fn is_admin(env: &Env, caller: &Address) -> bool {
        let admin: Address = env.storage().instance().get(ADMIN_KEY).unwrap();
        admin == *caller
    }
    
    // Check if an address is eligible to propose
    pub fn check_proposer_eligibility(env: &Env, proposer: &Address) -> Result<bool, Error> {
        let requirements: ProposalRequirements = env.storage().instance().get(REQUIREMENTS_KEY).unwrap();
        
        // Check if they are under the proposal limit
        let draft_proposals = Self::get_proposals_by_status(env, ProposalStatus::Draft);
        let active_proposals = Self::get_proposals_by_status(env, ProposalStatus::Active);
        
        let proposer_draft_count = draft_proposals.iter()
            .filter(|id| {
                let prop = Self::get_proposal(env, **id).unwrap();
                prop.proposer == *proposer
            })
            .count();
            
        let proposer_active_count = active_proposals.iter()
            .filter(|id| {
                let prop = Self::get_proposal(env, **id).unwrap();
                prop.proposer == *proposer
            })
            .count();
            
        if (proposer_draft_count + proposer_active_count) as u32 >= requirements.proposal_limit {
            return Err(Error::ProposalLimitReached);
        }
        
        // Check cooldown period
        let latest_proposal_time = Self::get_latest_proposal_time(env, proposer);
        if let Some(time) = latest_proposal_time {
            let current_time = env.ledger().timestamp();
            if current_time < time + requirements.cooldown_period {
                return Err(Error::ProposalInCooldown);
            }
        }
        
        // TODO: Check if they have staked enough tokens (would require token integration)
        // For now, just return true as this would be implemented with a token contract
        Ok(true)
    }
    
    // Get the latest proposal time for an address
    fn get_latest_proposal_time(env: &Env, proposer: &Address) -> Option<u64> {
        let all_proposals = Self::get_all_proposals(env);
        
        let mut latest_time: Option<u64> = None;
        
        for id in all_proposals.iter() {
            let proposal = Self::get_proposal(env, *id).unwrap();
            if proposal.proposer == *proposer {
                match latest_time {
                    None => latest_time = Some(proposal.created_at),
                    Some(time) if proposal.created_at > time => latest_time = Some(proposal.created_at),
                    _ => {}
                }
            }
        }
        
        latest_time
    }
    
    // Create a new proposal
    pub fn create_proposal(
        env: &Env,
        proposer: &Address,
        title: Symbol,
        description: Symbol,
        proposal_type: ProposalType,
        actions: Vec<Action>,
        voting_config: VotingConfig,
    ) -> Result<u32, Error> {
        // Get the next proposal ID
        let mut proposal_counter: u32 = env.storage().instance().get(PROPOSAL_COUNTER_KEY).unwrap();
        proposal_counter += 1;
        
        // Create the proposal
        let proposal = Proposal {
            id: proposal_counter,
            proposer: proposer.clone(),
            title,
            description,
            proposal_type,
            status: ProposalStatus::Draft,
            created_at: env.ledger().timestamp(),
            activated_at: 0, // Will be set when activated
            voting_config,
            actions,
        };
        
        // Store the proposal
        let key = Self::get_proposal_key(proposal_counter);
        env.storage().instance().set(key, proposal.clone());
        
        // Update the proposal counter
        env.storage().instance().set(PROPOSAL_COUNTER_KEY, proposal_counter);
        
        // Add to draft proposals list
        Self::add_to_status_list(env, proposal_counter, ProposalStatus::Draft);
        
        Ok(proposal_counter)
    }
    
    // Activate a proposal (move from Draft to Active)
    pub fn activate_proposal(env: &Env, proposal_id: u32) -> Result<(), Error> {
        let key = Self::get_proposal_key(proposal_id);
        let mut proposal: Proposal = env.storage().instance().get(key.clone()).unwrap_or_else(|| {
            panic!("proposal not found")
        });
        
        if proposal.status != ProposalStatus::Draft {
            return Err(Error::InvalidProposalStatus);
        }
        
        // Update the proposal status
        proposal.status = ProposalStatus::Active;
        proposal.activated_at = env.ledger().timestamp();
        
        // Save the updated proposal
        env.storage().instance().set(key, proposal);
        
        // Update status lists
        Self::remove_from_status_list(env, proposal_id, ProposalStatus::Draft);
        Self::add_to_status_list(env, proposal_id, ProposalStatus::Active);
        
        Ok(())
    }
    
    // Cancel a proposal
    pub fn cancel_proposal(env: &Env, proposal_id: u32) -> Result<(), Error> {
        let key = Self::get_proposal_key(proposal_id);
        let mut proposal: Proposal = env.storage().instance().get(key.clone()).unwrap_or_else(|| {
            panic!("proposal not found")
        });
        
        let old_status = proposal.status.clone();
        
        if old_status != ProposalStatus::Draft && old_status != ProposalStatus::Active {
            return Err(Error::InvalidProposalStatus);
        }
        
        // Update the proposal status
        proposal.status = ProposalStatus::Canceled;
        
        // Save the updated proposal
        env.storage().instance().set(key, proposal);
        
        // Update status lists
        Self::remove_from_status_list(env, proposal_id, old_status);
        Self::add_to_status_list(env, proposal_id, ProposalStatus::Canceled);
        
        Ok(())
    }
    
    // Mark a proposal as passed
    pub fn mark_passed(env: &Env, proposal_id: u32) -> Result<(), Error> {
        let key = Self::get_proposal_key(proposal_id);
        let mut proposal: Proposal = env.storage().instance().get(key.clone()).unwrap_or_else(|| {
            panic!("proposal not found")
        });
        
        if proposal.status != ProposalStatus::Active {
            return Err(Error::InvalidProposalStatus);
        }
        
        // Update the proposal status
        proposal.status = ProposalStatus::Passed;
        
        // Save the updated proposal
        env.storage().instance().set(key, proposal);
        
        // Update status lists
        Self::remove_from_status_list(env, proposal_id, ProposalStatus::Active);
        Self::add_to_status_list(env, proposal_id, ProposalStatus::Passed);
        
        Ok(())
    }
    
    // Mark a proposal as rejected
    pub fn mark_rejected(env: &Env, proposal_id: u32) -> Result<(), Error> {
        let key = Self::get_proposal_key(proposal_id);
        let mut proposal: Proposal = env.storage().instance().get(key.clone()).unwrap_or_else(|| {
            panic!("proposal not found")
        });
        
        if proposal.status != ProposalStatus::Active {
            return Err(Error::InvalidProposalStatus);
        }
        
        // Update the proposal status
        proposal.status = ProposalStatus::Rejected;
        
        // Save the updated proposal
        env.storage().instance().set(key, proposal);
        
        // Update status lists
        Self::remove_from_status_list(env, proposal_id, ProposalStatus::Active);
        Self::add_to_status_list(env, proposal_id, ProposalStatus::Rejected);
        
        Ok(())
    }
    
    // Mark a proposal as executed
    pub fn mark_executed(env: &Env, proposal_id: u32) -> Result<(), Error> {
        let key = Self::get_proposal_key(proposal_id);
        let mut proposal: Proposal = env.storage().instance().get(key.clone()).unwrap_or_else(|| {
            panic!("proposal not found")
        });
        
        if proposal.status != ProposalStatus::Passed {
            return Err(Error::InvalidProposalStatus);
        }
        
        // Update the proposal status
        proposal.status = ProposalStatus::Executed;
        
        // Save the updated proposal
        env.storage().instance().set(key, proposal);
        
        // Update status lists
        Self::remove_from_status_list(env, proposal_id, ProposalStatus::Passed);
        Self::add_to_status_list(env, proposal_id, ProposalStatus::Executed);
        
        Ok(())
    }
    
    // Get a proposal by ID
    pub fn get_proposal(env: &Env, proposal_id: u32) -> Result<Proposal, Error> {
        let key = Self::get_proposal_key(proposal_id);
        
        match env.storage().instance().get::<_, Proposal>(key) {
            Some(proposal) => Ok(proposal),
            None => Err(Error::ProposalNotFound),
        }
    }
    
    // Get all proposals
    pub fn get_all_proposals(env: &Env) -> Vec<u32> {
        let draft = Self::get_proposals_by_status(env, ProposalStatus::Draft);
        let active = Self::get_proposals_by_status(env, ProposalStatus::Active);
        let passed = Self::get_proposals_by_status(env, ProposalStatus::Passed);
        let rejected = Self::get_proposals_by_status(env, ProposalStatus::Rejected);
        let executed = Self::get_proposals_by_status(env, ProposalStatus::Executed);
        let canceled = Self::get_proposals_by_status(env, ProposalStatus::Canceled);
        
        let mut all = vec![env];
        
        for id in draft.iter() {
            all.push_back(*id);
        }
        
        for id in active.iter() {
            all.push_back(*id);
        }
        
        for id in passed.iter() {
            all.push_back(*id);
        }
        
        for id in rejected.iter() {
            all.push_back(*id);
        }
        
        for id in executed.iter() {
            all.push_back(*id);
        }
        
        for id in canceled.iter() {
            all.push_back(*id);
        }
        
        all
    }
    
    // Get proposals by status
    pub fn get_proposals_by_status(env: &Env, status: ProposalStatus) -> Vec<u32> {
        let key = Self::get_status_key(status);
        env.storage().instance().get(key).unwrap_or_else(|| vec![env])
    }
    
    // Helper methods for storage keys
    fn get_proposal_key(proposal_id: u32) -> Symbol {
        Symbol::new(format!("{}_{}", PROPOSAL_PREFIX, proposal_id))
    }
    
    fn get_status_key(status: ProposalStatus) -> Symbol {
        Symbol::new(format!("{}_{}", PROPOSAL_STATUS_PREFIX, status as u32))
    }
    
    // Helper methods for managing status lists
    fn add_to_status_list(env: &Env, proposal_id: u32, status: ProposalStatus) {
        let key = Self::get_status_key(status);
        let mut list: Vec<u32> = env.storage().instance().get(key.clone()).unwrap_or_else(|| vec![env]);
        
        if !list.contains(proposal_id) {
            list.push_back(proposal_id);
            env.storage().instance().set(key, list);
        }
    }
    
    fn remove_from_status_list(env: &Env, proposal_id: u32, status: ProposalStatus) {
        let key = Self::get_status_key(status);
        let mut list: Vec<u32> = env.storage().instance().get(key.clone()).unwrap_or_else(|| vec![env]);
        
        let mut new_list = vec![env];
        for id in list.iter() {
            if *id != proposal_id {
                new_list.push_back(*id);
            }
        }
        
        env.storage().instance().set(key, new_list);
    }
}

// Helper to convert u32 to ProposalStatus
impl ProposalStatus {
    fn from_u32(status: u32) -> Self {
        match status {
            0 => ProposalStatus::Draft,
            1 => ProposalStatus::Active,
            2 => ProposalStatus::Passed,
            3 => ProposalStatus::Rejected,
            4 => ProposalStatus::Executed,
            5 => ProposalStatus::Canceled,
            _ => panic!("invalid proposal status"),
        }
    }
}
