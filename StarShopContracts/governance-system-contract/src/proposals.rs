use crate::types::{
    Action, Error, Proposal, ProposalRequirements, ProposalStatus, ProposalType, VotingConfig,
    ADMIN_KEY, PROPOSAL_COUNTER_KEY, REQUIREMENTS_KEY,
};
use soroban_sdk::{symbol_short, Address, Env, Symbol, Vec};

pub struct ProposalManager;

impl ProposalManager {
    pub fn init(env: &Env, admin: &Address) {
        if env.storage().instance().has(&ADMIN_KEY) {
            panic!("Already initialized");
        }
        env.storage().instance().set(&ADMIN_KEY, admin);
        env.storage().instance().set(&PROPOSAL_COUNTER_KEY, &0u32);
        let requirements = ProposalRequirements {
            cooldown_period: 86400, // 24 hours
            required_stake: 1000,   // 1000 tokens
            proposal_limit: 5,
        };
        env.storage()
            .instance()
            .set(&REQUIREMENTS_KEY, &requirements);
        for status in 0..6 {
            let status_key = Self::get_status_key(env, ProposalStatus::from_u32(status));
            env.storage().instance().set(&status_key, &Vec::<u32>::new(env));
        }
    }

    pub fn is_admin(env: &Env, caller: &Address) -> bool {
        let admin: Address = env.storage().instance().get(&ADMIN_KEY).unwrap();
        admin == *caller
    }

    pub fn check_proposer_eligibility(env: &Env, proposer: &Address) -> Result<bool, Error> {
        let requirements: ProposalRequirements =
            env.storage().instance().get(&REQUIREMENTS_KEY).unwrap();
        let draft_proposals = Self::get_proposals_by_status(env, ProposalStatus::Draft);
        let active_proposals = Self::get_proposals_by_status(env, ProposalStatus::Active);
        let proposer_count = draft_proposals
            .iter()
            .chain(active_proposals.iter())
            .filter(|id| {
                let prop = Self::get_proposal(env, *id).unwrap();
                prop.proposer == *proposer
            })
            .count();
        if proposer_count as u32 >= requirements.proposal_limit {
            return Err(Error::ProposalLimitReached);
        }
        let latest_proposal_time = Self::get_latest_proposal_time(env, proposer);
        if let Some(time) = latest_proposal_time {
            let current_time = env.ledger().timestamp();
            if current_time < time + requirements.cooldown_period {
                return Err(Error::ProposalInCooldown);
            }
        }
        // Placeholder: Check token stake
        let stake = 1000i128; // Simulate token balance
        if stake < requirements.required_stake {
            return Err(Error::InsufficientStake);
        }
        Ok(true)
    }

    fn get_latest_proposal_time(env: &Env, proposer: &Address) -> Option<u64> {
        let all_proposals = Self::get_all_proposals(env);
        let mut latest_time: Option<u64> = None;
        for id in all_proposals.iter() {
            let proposal = Self::get_proposal(env, id).unwrap();
            if proposal.proposer == *proposer
                && (latest_time.is_none() || proposal.created_at > latest_time.unwrap())
            {
                latest_time = Some(proposal.created_at);
            }
        }
        latest_time
    }

    pub fn create_proposal(
        env: &Env,
        proposer: &Address,
        title: Symbol,
        description: Symbol,
        proposal_type: ProposalType,
        actions: Vec<Action>,
        voting_config: VotingConfig,
    ) -> Result<u32, Error> {
        if title.to_string().len() > 100 || description.to_string().len() > 1000 {
            return Err(Error::InvalidProposalStatus); // Reuse error for simplicity
        }
        if actions.is_empty() || actions.len() > 5 {
            return Err(Error::InvalidAction);
        }
        let mut proposal_counter: u32 = env
            .storage()
            .instance()
            .get(&PROPOSAL_COUNTER_KEY)
            .unwrap_or(0);
        proposal_counter += 1;
        let proposal = Proposal {
            id: proposal_counter,
            proposer: proposer.clone(),
            title: title.clone(),
            description,
            proposal_type,
            status: ProposalStatus::Draft,
            created_at: env.ledger().timestamp(),
            activated_at: 0,
            voting_config,
            actions,
        };
        let key = Self::get_proposal_key(env, proposal_counter);
        env.storage().instance().set(&key, &proposal);
        env.storage()
            .instance()
            .set(&PROPOSAL_COUNTER_KEY, &proposal_counter);
        Self::add_to_status_list(env, proposal_counter, ProposalStatus::Draft);
        env.events().publish(
            (symbol_short!("proposal"), symbol_short!("created")),
            (proposal_counter, proposer, title),
        );
        Ok(proposal_counter)
    }

    pub fn activate_proposal(env: &Env, proposal_id: u32) -> Result<(), Error> {
        let key = Self::get_proposal_key(env, proposal_id);
        let mut proposal: Proposal = env
            .storage()
            .instance()
            .get(&key)
            .ok_or(Error::ProposalNotFound)?;
        if proposal.status != ProposalStatus::Draft {
            return Err(Error::InvalidProposalStatus);
        }
        proposal.status = ProposalStatus::Active;
        proposal.activated_at = env.ledger().timestamp();
        env.storage().instance().set(&key, &proposal);
        Self::remove_from_status_list(env, proposal_id, ProposalStatus::Draft);
        Self::add_to_status_list(env, proposal_id, ProposalStatus::Active);
        env.events().publish(
            (symbol_short!("proposal"), symbol_short!("activated")),
            proposal_id,
        );
        Ok(())
    }

    pub fn cancel_proposal(env: &Env, proposal_id: u32) -> Result<(), Error> {
        let key = Self::get_proposal_key(env, proposal_id);
        let mut proposal: Proposal = env
            .storage()
            .instance()
            .get(&key)
            .ok_or(Error::ProposalNotFound)?;
        let old_status = proposal.status.clone();
        if old_status != ProposalStatus::Draft && old_status != ProposalStatus::Active {
            return Err(Error::InvalidProposalStatus);
        }
        proposal.status = ProposalStatus::Canceled;
        env.storage().instance().set(&key, &proposal);
        Self::remove_from_status_list(env, proposal_id, old_status);
        Self::add_to_status_list(env, proposal_id, ProposalStatus::Canceled);
        env.events().publish(
            (symbol_short!("proposal"), symbol_short!("canceled")),
            proposal_id,
        );
        Ok(())
    }

    pub fn mark_passed(env: &Env, proposal_id: u32) -> Result<(), Error> {
        let key = Self::get_proposal_key(env, proposal_id);
        let mut proposal: Proposal = env
            .storage()
            .instance()
            .get(&key)
            .ok_or(Error::ProposalNotFound)?;
        if proposal.status != ProposalStatus::Active {
            return Err(Error::InvalidProposalStatus);
        }
        proposal.status = ProposalStatus::Passed;
        env.storage().instance().set(&key, &proposal);
        Self::remove_from_status_list(env, proposal_id, ProposalStatus::Active);
        Self::add_to_status_list(env, proposal_id, ProposalStatus::Passed);
        env.events().publish(
            (symbol_short!("proposal"), symbol_short!("passed")),
            proposal_id,
        );
        Ok(())
    }

    pub fn mark_rejected(env: &Env, proposal_id: u32) -> Result<(), Error> {
        let key = Self::get_proposal_key(env, proposal_id);
        let mut proposal: Proposal = env
            .storage()
            .instance()
            .get(&key)
            .ok_or(Error::ProposalNotFound)?;
        if proposal.status != ProposalStatus::Active {
            return Err(Error::InvalidProposalStatus);
        }
        proposal.status = ProposalStatus::Rejected;
        env.storage().instance().set(&key, &proposal);
        Self::remove_from_status_list(env, proposal_id, ProposalStatus::Active);
        Self::add_to_status_list(env, proposal_id, ProposalStatus::Rejected);
        env.events().publish(
            (symbol_short!("proposal"), symbol_short!("rejected")),
            proposal_id,
        );
        Ok(())
    }

    pub fn mark_executed(env: &Env, proposal_id: u32) -> Result<(), Error> {
        let key = Self::get_proposal_key(env, proposal_id);
        let mut proposal: Proposal = env
            .storage()
            .instance()
            .get(&key)
            .ok_or(Error::ProposalNotFound)?;
        if proposal.status != ProposalStatus::Passed {
            return Err(Error::InvalidProposalStatus);
        }
        proposal.status = ProposalStatus::Executed;
        env.storage().instance().set(&key, &proposal);
        Self::remove_from_status_list(env, proposal_id, ProposalStatus::Passed);
        Self::add_to_status_list(env, proposal_id, ProposalStatus::Executed);
        env.events().publish(
            (symbol_short!("proposal"), symbol_short!("executed")),
            proposal_id,
        );
        Ok(())
    }

    pub fn get_proposal(env: &Env, proposal_id: u32) -> Result<Proposal, Error> {
        let key = Self::get_proposal_key(env, proposal_id);
        env.storage()
            .instance()
            .get(&key)
            .ok_or(Error::ProposalNotFound)
    }

    pub fn get_proposals_by_status(env: &Env, status: ProposalStatus) -> Vec<u32> {
        let key = Self::get_status_key(env, status);
        env.storage()
            .instance()
            .get(&key)
            .unwrap_or_else(|| Vec::<u32>::new(env))
    }

    fn get_all_proposals(env: &Env) -> Vec<u32> {
        let statuses = [
            ProposalStatus::Draft,
            ProposalStatus::Active,
            ProposalStatus::Passed,
            ProposalStatus::Rejected,
            ProposalStatus::Executed,
            ProposalStatus::Canceled,
        ];
        let mut all = Vec::<u32>::new(env);
        for status in statuses.iter() {
            let proposals = Self::get_proposals_by_status(env, status.clone());
            for id in proposals.iter() {
                all.push_back(id);
            }
        }
        all
    }

    fn get_proposal_key(env: &Env, proposal_id: u32) -> Symbol {
        Symbol::new(&env, &format!("PROP_{}", proposal_id))
    }

    fn get_status_key(env: &Env, status: ProposalStatus) -> Symbol {
        Symbol::new(&env, &format!("STAT_{}", status as u32))
    }

    fn add_to_status_list(env: &Env, proposal_id: u32, status: ProposalStatus) {
        let key = Self::get_status_key(env, status);
        let mut list: Vec<u32> = env
            .storage()
            .instance()
            .get(&key)
            .unwrap_or_else(|| Vec::<u32>::new(env));
        if !list.contains(&proposal_id) {
            list.push_back(proposal_id);
            env.storage().instance().set(&key, &list);
        }
    }

    fn remove_from_status_list(env: &Env, proposal_id: u32, status: ProposalStatus) {
        let key = Self::get_status_key(env, status);
        let list: Vec<u32> = env
            .storage()
            .instance()
            .get(&key)
            .unwrap_or_else(|| Vec::<u32>::new(env));
        let mut new_list = Vec::<u32>::new(env);
        for id in list.iter() {
            if id != proposal_id {
                new_list.push_back(id);
            }
        }
        env.storage().instance().set(&key, &new_list);
    }
}

impl ProposalStatus {
    pub fn from_u32(status: u32) -> Self {
        match status {
            0 => ProposalStatus::Draft,
            1 => ProposalStatus::Active,
            2 => ProposalStatus::Passed,
            3 => ProposalStatus::Rejected,
            4 => ProposalStatus::Executed,
            5 => ProposalStatus::Canceled,
            _ => panic!("Invalid proposal status"),
        }
    }
}
