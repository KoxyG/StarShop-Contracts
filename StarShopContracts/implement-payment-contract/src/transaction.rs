use soroban_sdk::{contract, contractimpl, Address, Env};
use soroban_sdk::token::{TokenClient, TokenIdentifier};


#[contract]
pub struct TransactionContract


#[contractimpl]
impl TransactionContract {

  pub fn payment_transaction (e: Env, signer: Address, to: Address, amount_to_deposit: i128) -> Result<(), TransactionError> {
    signer.require_auth();

    // xml token id
    let xml_token_id = TokenIdentifier::native();

    // initialize xml token transaction
    let xlm_client = TokenClient::new(&e, &xml_token_id);

    // Get the signer's balance
    let signer_balance = xlm_client.balance(&signer);

    if signer_balance < amount_to_deposit {
       return Err(TransactionError::InsufficientFunds);
    }


   //  let contract_address = e.current_contract_address();

    // Transfer XLM from signer to contract
    xlm_client.transfer(&signer, &to, &amount_to_deposit);

    Ok()

  }

}


#[derive(Debug)]
pub enum TransactionError {
    InsufficientFunds,
}

