use crate::execution::ExecutionEngine;
use crate::proposals::ProposalManager;
use crate::types::{Action, Error, Proposal, ProposalStatus, ProposalType, VotingConfig};
use crate::voting::VotingSystem;
use crate::weights::WeightCalculator;
use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env, String, Symbol, Vec};

#[contract]
pub struct GovernanceContract;

#[contractimpl]
impl GovernanceContract {
    pub fn initialize(
        env: Env,
        admin: Address,
        token: Address,
        referral_contract: Address,
        auction_contract: Address,
        config: VotingConfig,
    ) -> Result<(), Error> {
        admin.require_auth();
        env.storage()
            .instance()
            .set(&crate::types::TOKEN_KEY, &token);
        env.storage()
            .instance()
            .set(&crate::types::REFERRAL_KEY, &referral_contract);
        env.storage()
            .instance()
            .set(&crate::types::AUCTION_KEY, &auction_contract);
        
        ProposalManager::init(&env, &admin, config);
        WeightCalculator::init(&env, &token);

        env.events().publish(
            (symbol_short!("govern"), symbol_short!("init")),
            (admin, token, referral_contract, auction_contract),
        );

        Ok(())
    }

    pub fn create_proposal(
        env: Env,
        proposer: Address,
        title: Symbol,
        description: Symbol,
        metadata_hash: String,
        proposal_type: ProposalType,
        actions: Vec<Action>,
        voting_config: VotingConfig,
    ) -> Result<u32, Error> {
        proposer.require_auth();
        if !ProposalManager::check_proposer_eligibility(&env, &proposer, &proposal_type)? {
            return Err(Error::NotEligibleToPropose);
        }
        ProposalManager::create_proposal(
            &env,
            &proposer,
            title,
            description,
            metadata_hash,
            proposal_type,
            actions,
            voting_config,
        )
    }

    pub fn activate_proposal(env: Env, caller: Address, proposal_id: u32) -> Result<(), Error> {
        caller.require_auth();
        let _proposal = ProposalManager::get_proposal(&env, proposal_id)?;
        if !ProposalManager::is_moderator(&env, &caller) {
            return Err(Error::Unauthorized);
        }
        WeightCalculator::take_snapshot(&env, proposal_id)?;
        ProposalManager::activate_proposal(&env, proposal_id)
    }

    pub fn cancel_proposal(env: Env, caller: Address, proposal_id: u32) -> Result<(), Error> {
        caller.require_auth();
        let proposal = ProposalManager::get_proposal(&env, proposal_id)?;
        if proposal.proposer != caller
            && !ProposalManager::is_admin(&env, &caller)
            && !ProposalManager::is_moderator(&env, &caller)
        {
            return Err(Error::Unauthorized);
        }
        if proposal.status != ProposalStatus::Draft && proposal.status != ProposalStatus::Active {
            return Err(Error::InvalidProposalStatus);
        }
        ProposalManager::cancel_proposal(&env, proposal_id)
    }

    pub fn veto_proposal(env: Env, moderator: Address, proposal_id: u32) -> Result<(), Error> {
        moderator.require_auth();
        ProposalManager::veto_proposal(&env, &moderator, proposal_id)
    }

    pub fn cast_vote(
        env: Env,
        voter: Address,
        proposal_id: u32,
        support: bool,
    ) -> Result<(), Error> {
        voter.require_auth();
        let proposal = ProposalManager::get_proposal(&env, proposal_id)?;
        if proposal.status != ProposalStatus::Active {
            return Err(Error::ProposalNotActive);
        }
        let weight = if proposal.voting_config.one_address_one_vote {
            1
        } else {
            WeightCalculator::get_weight(&env, &voter, proposal_id)?
        };
        if weight <= 0 {
            return Err(Error::NoVotingPower);
        }
        VotingSystem::cast_vote(&env, proposal_id, &voter, support, weight)?;
        if VotingSystem::check_voting_ended(&env, proposal_id, &proposal.voting_config)? {
            let passed = VotingSystem::tally_votes(&env, proposal_id, &proposal.voting_config)?;
            if passed {
                ProposalManager::mark_passed(&env, proposal_id)?;
            } else {
                ProposalManager::mark_rejected(&env, proposal_id)?;
            }
        }
        Ok(())
    }

    pub fn delegate_vote(env: Env, delegator: Address, delegatee: Address) -> Result<(), Error> {
        delegator.require_auth();
        WeightCalculator::delegate(&env, &delegator, &delegatee)
    }

    pub fn get_vote_weight(env: Env, voter: Address, proposal_id: u32) -> Result<i128, Error> {
        WeightCalculator::get_weight(&env, &voter, proposal_id)
    }

    pub fn execute_proposal(env: Env, executor: Address, proposal_id: u32) -> Result<(), Error> {
        executor.require_auth();
        let proposal = ProposalManager::get_proposal(&env, proposal_id)?;
        if proposal.status != ProposalStatus::Passed {
            return Err(Error::ProposalNotExecutable);
        }
        if !ExecutionEngine::check_execution_delay(&env, proposal_id, &proposal)? {
            return Err(Error::ExecutionDelayNotMet);
        }
        ExecutionEngine::execute(&env, &executor, proposal_id, &proposal)?;
        ProposalManager::mark_executed(&env, proposal_id)
    }

    pub fn get_proposal(env: Env, proposal_id: u32) -> Result<Proposal, Error> {
        ProposalManager::get_proposal(&env, proposal_id)
    }

    pub fn get_active_proposals(env: Env) -> Vec<u32> {
        ProposalManager::get_proposals_by_status(&env, ProposalStatus::Active)
    }

    pub fn get_executable_proposals(env: Env) -> Vec<u32> {
        ProposalManager::get_proposals_by_status(&env, ProposalStatus::Passed)
    }
}
