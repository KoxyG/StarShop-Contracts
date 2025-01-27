use soroban_sdk::{contract, contractimpl, Address, Env};
use soroban_sdk::token::{TokenClient, TokenIdentifier};


#[contract]
pub struct DisputeContract


#[contractimpl]
impl DisputeContract {

  pub fn resolve_dispute (e: Env,
        arbitrator: Address,
        buyer: Address,
        seller: Address,
        refund_amount: i128,
        decision: DisputeDecision) -> Result<(), DisputeError> {
    
    
    arbitrator.require_auth();

    let xlm_token_id = TokenIdentifier::native();
    let xlm_client = TokenClient::new(&e, &xlm_token_id);
    let contract_address = e.current_contract_address();


    let arbitrator_balance = xlm_client.balance(&arbitrator);
        if arbitrator_balance < refund_amount {
            return Err(ContractError::InsufficientFunds);
        }

   //  let contract_address = e.current_contract_address();

    // Transfer XLM from signer to contract
   match decision {
            DisputeDecision::RefundToBuyer => {
                xlm_client.transfer(&arbitrator, &buyer, &refund_amount);
            }
            DisputeDecision::ReleaseToSeller => {
                xlm_client.transfer(&arbitrator, &seller, &refund_amount);
            }
        }

     Ok(())
  }

}


#[derive(Debug)]
pub enum DisputeError {
    InsufficientFunds,
}

#[derive(Clone, Debug)]
pub enum DisputeDecision {
    RefundToBuyer,
    ReleaseToSeller,
}
