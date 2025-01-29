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
    
    if amount_to_deposit <= 0 {
        return Err(DisputeError::InvalidAmount);
    }

    if buyer == seller {
        return Err(DisputeError::CanNotBeTheSame);
    }

    if arbitrator == seller {
        return Err(DisputeError::CanNotBeTheSame);
    }

    if arbitrator == buyer {
        return Err(DisputeError::CanNotBeTheSame);
    }

    let xlm_token_id = TokenIdentifier::native();
    let xlm_client = TokenClient::new(&e, &xlm_token_id);


    // let contract_address = e.current_contract_address();


    let arbitrator_balance = xlm_client.balance(&arbitrator);
        if arbitrator_balance < refund_amount {
            return Err(DisputeError::InsufficientFunds);
        }
        
    // Transfer XLM base on decision. 
   match decision {
            DisputeDecision::RefundToBuyer => {
                if xlm_client.transfer(&arbitrator, &buyer, &refund_amount).is_err() {
                    return Err(DisputeError::TransferFailed);
                }
            }
            DisputeDecision::ReleaseToSeller => {
                if xlm_client.transfer(&arbitrator, &seller, &refund_amount).is_err() {
                    return Err(DisputeError::TransferFailed);
                }
            }
        }
    
   // emit event
   let topics = (symbol_short!("dispute"));
   let event_payload = vec![e, arbitrator, seller, buyer, refund_amount];
   e.events().publish(topics, event_payload);
   Ok(())
  }

}


#[derive(Debug)]
pub enum DisputeError {
    InsufficientFunds,
    TransferFailed,
    CanNotBeTheSame,
}

#[derive(Clone, Debug)]
pub enum DisputeDecision {
    RefundToBuyer,
    ReleaseToSeller,
}
