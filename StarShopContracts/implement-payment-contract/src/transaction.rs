use soroban_sdk::{contract, contractimpl, Address, Env, symbol_short};
use soroban_sdk::token::{TokenClient, TokenIdentifier};


#[contract]
pub struct TransactionContract


#[contractimpl]
impl TransactionContract {

  pub fn payment_transaction (e: Env, signer: Address, to: Address, amount_to_deposit: i128) -> Result<(), TransactionError> {
    signer.require_auth();

    // check for invalid amount
    if amount_to_deposit <= 0 {
        return Err(TransactionError::InvalidAmount);
    }

    // xml token id
    let xml_token_id = TokenIdentifier::native();

    // initialize xml token transaction
    let xlm_client = TokenClient::new(&e, &xml_token_id);

    // Get the signer's balance
    let signer_balance = xlm_client.balance(&signer);

    if signer_balance < amount_to_deposit {
       return Err(TransactionError::InsufficientFunds);
    }

    // Ensure the signer is authorized to send funds
    if signer == to {
        return Err(TransactionError::UnauthorizedAccess);
    }

   //  let contract_address = e.current_contract_address();

    // Transfer XLM from signer to contract
   if xlm_client.transfer(&signer, &to, &amount_to_deposit).is_err() {
      return Err(TransactionError::TransferFailed);
   };

   // emit event
   let topics = (symbol_short!("payment_transaction"));
   let event_payload = vec![e, signer, to, amount_to_deposit];
   e.events().publish(topics, event_payload);
   
   Ok()

  }

}


#[derive(Debug)]
pub enum TransactionError {
    InsufficientFunds,
    InvalidAmount,
    UnauthorizedAccess,
    TransferFailed
}

