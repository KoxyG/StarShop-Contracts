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

    let signer_balance = xlm_client.balance(&signer);

    // let contract_address = e.current_contract_address();

    // Transfer XLM from seller to  buyer
    xlm_client.transfer(&seller, &buyer, &amount);

    Ok()

  }

}


#[derive(Debug)]
pub enum RefundError {
    InsufficientFunds,
}

