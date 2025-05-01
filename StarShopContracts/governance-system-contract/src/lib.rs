cat > StarShopContracts/governance-system-contract/src/lib.rs << 'EOF'
#![no_std]
use soroban_sdk::{contract, contractimpl, Address, Env, Symbol, Vec};

pub mod proposals;
pub mod voting;
pub mod weights;
pub mod execution;
pub mod types;

use proposals::ProposalManager;
use voting::VotingSystem;
use weights::WeightCalculator;
use execution::ExecutionEngine;
use types::{Error, ProposalStatus, ProposalType, Proposal, Action, VotingConfig};

pub trait GovernanceTrait {
    // Initialization function
    fn init(env: Env, admin: Address);
    
    // Proposal lifecycle functions
    fn create_proposal(
        env: Env, 
        proposer: Address, 
        title: Symbol, 
        description: Symbol, 
        proposal_type: ProposalType, 
        actions: Vec<Action>, 
        voting_config: VotingConfig
    ) -> Result<u32, Error>;
    
    fn activate_proposal(env: Env, caller: Address, proposal_id: u32) -> Result<(), Error>;
    fn cancel_proposal(env: Env, caller: Address, proposal_id: u32) -> Result<(), Error>;
    
    // Voting functions
    fn cast_vote(env: Env, voter: Address, proposal_id: u32, support: bool) -> Result<(), Error>;
    fn delegate_vote(env: Env, delegator: Address, delegatee: Address) -> Result<(), Error>;
    fn get_vote_weight(env: Env, voter: Address) -> i128;
    
    // Execution functions
    fn execute_proposal(env: Env, executor: Address, proposal_id: u32) -> Result<(), Error>;
    
    // View functions
    fn get_proposal(env: Env, proposal_id: u32) -> Result<Proposal, Error>;
    fn get_active_proposals(env: Env) -> Vec<u32>;
    fn get_executable_proposals(env: Env) -> Vec<u32>;
}

#[contract]
pub struct GovernanceSystem;

#[contractimpl]
impl GovernanceTrait for GovernanceSystem {
    fn init(env: Env, admin: Address) {
        ProposalManager::init(&env, &admin);
        VotingSystem::init(&env);
        WeightCalculator::init(&env);
        ExecutionEngine::init(&env, &admin);
    }
    
    fn create_proposal(
        env: Env, 
        proposer: Address, 
        title: Symbol, 
        description: Symbol, 
        proposal_type: ProposalType, 
        actions: Vec<Action>, 
        voting_config: VotingConfig
    ) -> Result<u32, Error> {
        // Validate proposer has rights to create proposal
        if !ProposalManager::check_proposer_eligibility(&env, &proposer)? {
            return Err(Error::NotEligibleToPropose);
        }
        
        // Create the proposal in Draft state
        let proposal_id = ProposalManager::create_proposal(
            &env, 
            &proposer, 
            title, 
            description, 
            proposal_type, 
            actions, 
            voting_config
        )?;
        
        Ok(proposal_id)
    }
    
    fn activate_proposal(env: Env, caller: Address, proposal_id: u32) -> Result<(), Error> {
        // Check if caller is the proposer or admin
        let proposal = ProposalManager::get_proposal(&env, proposal_id)?;
        
        if proposal.proposer != caller && !ProposalManager::is_admin(&env, &caller) {
            return Err(Error::Unauthorized);
        }
        
        if proposal.status != ProposalStatus::Draft {
            return Err(Error::InvalidProposalStatus);
        }
        
        // Take a snapshot of token balances for voting weights
        WeightCalculator::take_snapshot(&env, proposal_id)?;
        
        // Activate the proposal
        ProposalManager::activate_proposal(&env, proposal_id)
    }
    
    fn cancel_proposal(env: Env, caller: Address, proposal_id: u32) -> Result<(), Error> {
        // Check if caller is the proposer or admin
        let proposal = ProposalManager::get_proposal(&env, proposal_id)?;
        
        if proposal.proposer != caller && !ProposalManager::is_admin(&env, &caller) {
            return Err(Error::Unauthorized);
        }
        
        if proposal.status != ProposalStatus::Draft && proposal.status != ProposalStatus::Active {
            return Err(Error::InvalidProposalStatus);
        }
        
        // Cancel the proposal
        ProposalManager::cancel_proposal(&env, proposal_id)
    }
    
    fn cast_vote(env: Env, voter: Address, proposal_id: u32, support: bool) -> Result<(), Error> {
        // Check if proposal is active
        let proposal = ProposalManager::get_proposal(&env, proposal_id)?;
        
        if proposal.status != ProposalStatus::Active {
            return Err(Error::ProposalNotActive);
        }
        
        // Calculate voter weight
        let weight = WeightCalculator::get_weight(&env, &voter, proposal_id)?;
        
        if weight <= 0 {
            return Err(Error::NoVotingPower);
        }
        
        // Cast the vote
        VotingSystem::cast_vote(&env, proposal_id, &voter, support, weight)?;
        
        // Check if the vote ended the voting period
        if VotingSystem::check_voting_ended(&env, proposal_id, &proposal.voting_config)? {
            // Update proposal status based on voting results
            let passed = VotingSystem::tally_votes(&env, proposal_id, &proposal.voting_config)?;
            
            if passed {
                ProposalManager::mark_passed(&env, proposal_id)?;
            } else {
                ProposalManager::mark_rejected(&env, proposal_id)?;
            }
        }
        
        Ok(())
    }
    
    fn delegate_vote(env: Env, delegator: Address, delegatee: Address) -> Result<(), Error> {
        WeightCalculator::delegate(&env, &delegator, &delegatee)
    }
    
    fn get_vote_weight(env: Env, voter: Address) -> i128 {
        WeightCalculator::get_base_weight(&env, &voter)
    }
    
    fn execute_proposal(env: Env, executor: Address, proposal_id: u32) -> Result<(), Error> {
        // Check if proposal is in Passed state
        let proposal = ProposalManager::get_proposal(&env, proposal_id)?;
        
        if proposal.status != ProposalStatus::Passed {
            return Err(Error::ProposalNotExecutable);
        }
        
        // Check execution delay
        if !ExecutionEngine::check_execution_delay(&env, proposal_id, &proposal)? {
            return Err(Error::ExecutionDelayNotMet);
        }
        
        // Execute the proposal actions
        ExecutionEngine::execute(&env, &executor, proposal_id, &proposal)?;
        
        // Mark proposal as executed
        ProposalManager::mark_executed(&env, proposal_id)
    }
    
    fn get_proposal(env: Env, proposal_id: u32) -> Result<Proposal, Error> {
        ProposalManager::get_proposal(&env, proposal_id)
    }
    
    fn get_active_proposals(env: Env) -> Vec<u32> {
        ProposalManager::get_proposals_by_status(&env, ProposalStatus::Active)
    }
    
    fn get_executable_proposals(env: Env) -> Vec<u32> {
        ProposalManager::get_proposals_by_status(&env, ProposalStatus::Passed)
    }
}
