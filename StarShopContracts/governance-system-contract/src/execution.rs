cat > StarShopContracts/governance-system-contract/src/execution.rs << 'EOF'
use soroban_sdk::{Address, Env, Map, Symbol, Vec, vec, BytesN, Val, IntoVal, TryFromVal, FromVal, Bytes, RawVal};
use crate::types::{Error, Proposal, Action, ADMIN_KEY};

pub struct ExecutionEngine;

impl ExecutionEngine {
    // Initialize the execution engine
    pub fn init(env: &Env, admin: &Address) {
        // No specific initialization needed at this point
    }
    
    // Check if execution delay has been met
    pub fn check_execution_delay(env: &Env, proposal_id: u32, proposal: &Proposal) -> Result<bool, Error> {
        let current_time = env.ledger().timestamp();
        
        // If proposal is not passed yet, it's not ready for execution
        if proposal.status != crate::types::ProposalStatus::Passed {
            return Ok(false);
        }
        
        // Calculate when execution is allowed based on the voting end time
        let voting_end_time = proposal.activated_at + proposal.voting_config.duration;
        let execution_time = voting_end_time + proposal.voting_config.execution_delay;
        
        // If current time is past the execution time, allow execution
        Ok(current_time >= execution_time)
    }
    
    // Execute a proposal's actions
    pub fn execute(env: &Env, executor: &Address, proposal_id: u32, proposal: &Proposal) -> Result<(), Error> {
        // Create execution log for transparency
        Self::log_execution_start(env, proposal_id, executor);
        
        // Execute each action in sequence
        for (i, action) in proposal.actions.iter().enumerate() {
            // Log action before execution
            Self::log_action_execution(env, proposal_id, i as u32);
            
            // Execute the action
            match Self::execute_action(env, action) {
                Ok(_) => {
                    // Log success
                    Self::log_action_result(env, proposal_id, i as u32, true);
                },
                Err(e) => {
                    // Log failure
                    Self::log_action_result(env, proposal_id, i as u32, false);
                    return Err(e);
                }
            }
        }
        
        // Log successful execution completion
        Self::log_execution_complete(env, proposal_id, true);
        
        Ok(())
    }
    
    // Execute a single action
    fn execute_action(env: &Env, action: &Action) -> Result<(), Error> {
        let contract_id = &action.contract_id;
        let function = action.function.clone();
        let args = action.args.clone();
        
        // Convert args from Bytes to Val
        let mut call_args = vec![env];
        for arg_bytes in args.iter() {
            // This is a simplified version - in a real implementation we'd need proper serialization
            // For now, assume all arguments are simple types like u32, i128, or String
            let arg_val: RawVal = arg_bytes.clone().into_val(env);
            call_args.push_back(arg_val);
        }
        
        // Call the contract
        let res = env.invoke_contract::<RawVal>(&contract_id, &function, call_args);
        
        match res {
            Ok(_) => Ok(()),
            Err(_) => Err(Error::ExecutionFailed),
        }
    }
    
    // Logging functions for transparency
    fn log_execution_start(env: &Env, proposal_id: u32, executor: &Address) {
        env.events().publish(
            (Symbol::new("governance"), Symbol::new("execute_start")),
            (proposal_id, executor)
        );
    }
    
    fn log_execution_complete(env: &Env, proposal_id: u32, success: bool) {
        env.events().publish(
            (Symbol::new("governance"), Symbol::new("execute_complete")),
            (proposal_id, success)
        );
    }
    
    fn log_action_execution(env: &Env, proposal_id: u32, action_index: u32) {
        env.events().publish(
            (Symbol::new("governance"), Symbol::new("action_execute")),
            (proposal_id, action_index)
        );
    }
    
    fn log_action_result(env: &Env, proposal_id: u32, action_index: u32, success: bool) {
        env.events().publish(
            (Symbol::new("governance"), Symbol::new("action_result")),
            (proposal_id, action_index, success)
        );
    }
}
