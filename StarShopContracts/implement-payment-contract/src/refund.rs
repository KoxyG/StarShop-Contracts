use soroban_sdk::{contract, contractimpl, Address, Env};
use soroban_sdk::token::{TokenClient, TokenIdentifier};


#[contract]
pub struct RefundContract


#[contractimpl]
impl RefundContract {

  pub fn refund (e: Env, seller: Address, buyer: Address, amount: i128) -> Result<(), RefundError> {
    seller.require_auth();

    let xml_token_id = TokenIdentifier::native();

    let xlm_client = TokenClient::new(&e, &xml_token_id);

    let seller_balance = xlm_client.balance(&seller);

    if seller_balance < amount {
       return Err(RefundError::InsufficientFunds);
    }

    // let contract_address = e.current_contract_address();

    // Transfer XLM from seller to  buyer
   if xlm_client.transfer(&seller, &buyer, &amount).is_err() {
      return Err(RefundError::TransferFailed);
   };

    Ok()

  }

}


#[derive(Debug)]
pub enum RefundError {
    InsufficientFunds,
    TransferFailed,
}

