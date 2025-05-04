use crate::types::{Action, Error, Proposal, ProposalStatus};
use soroban_sdk::{symbol_short, Address, Env};

pub struct ExecutionEngine;

impl ExecutionEngine {
    pub fn check_execution_delay(
        env: &Env,
        _proposal_id: u32,
        proposal: &Proposal,
    ) -> Result<bool, Error> {
        let current_time = env.ledger().timestamp();
        if proposal.status != ProposalStatus::Passed {
            return Ok(false);
        }
        let voting_end_time = proposal.activated_at + proposal.voting_config.duration;
        let execution_time = voting_end_time + proposal.voting_config.execution_delay;
        Ok(current_time >= execution_time)
    }

    pub fn execute(
        env: &Env,
        executor: &Address,
        proposal_id: u32,
        proposal: &Proposal,
    ) -> Result<(), Error> {
        Self::log_execution_start(env, proposal_id, executor);
        for (i, action) in proposal.actions.iter().enumerate() {
            Self::log_action_execution(env, proposal_id, i as u32);
            match Self::execute_action(env, &action) {
                Ok(_) => Self::log_action_result(env, proposal_id, i as u32, true),
                Err(e) => {
                    Self::log_action_result(env, proposal_id, i as u32, false);
                    return Err(e);
                }
            }
        }
        Self::log_execution_complete(env, proposal_id, true);
        Ok(())
    }

    fn execute_action(env: &Env, action: &Action) -> Result<(), Error> {
        // Placeholder: Simulate contract call
        Ok(())
    }

    fn log_execution_start(env: &Env, proposal_id: u32, executor: &Address) {
        env.events().publish(
            (symbol_short!("govern"), symbol_short!("start")),
            (proposal_id, executor),
        );
    }

    fn log_execution_complete(env: &Env, proposal_id: u32, success: bool) {
        env.events().publish(
            (symbol_short!("govern"), symbol_short!("complete")),
            (proposal_id, success),
        );
    }

    fn log_action_execution(env: &Env, proposal_id: u32, action_index: u32) {
        env.events().publish(
            (symbol_short!("govern"), symbol_short!("execute")),
            (proposal_id, action_index),
        );
    }

    fn log_action_result(env: &Env, proposal_id: u32, action_index: u32, success: bool) {
        env.events().publish(
            (symbol_short!("govern"), symbol_short!("result")),
            (proposal_id, action_index, success),
        );
    }
}
