use soroban_sdk::token::Client as TokenClient;
use soroban_sdk::{contract, contracterror, contractimpl, symbol_short, Address, Env};

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum TransactionError {
    InsufficientFunds = 1,
    TransferFailed = 2,
    InvalidAmount = 3,
    UnauthorizedAccess = 4,
}

#[contract]
pub struct TransactionContract;

#[contractimpl]
impl TransactionContract {
    pub fn process_deposit(
        e: Env,
        token_id: Address,
        signer: Address,
        to: Address,
        amount_to_deposit: i128,
    ) -> Result<(), TransactionError> {
        // Check authorization
        signer.require_auth();

        // Input validations
        if amount_to_deposit <= 0 {
            return Err(TransactionError::InvalidAmount);
        }

        if signer == to {
            return Err(TransactionError::UnauthorizedAccess);
        }

        let token = TokenClient::new(&e, &token_id);

        // Check balance
        let signer_balance = token.balance(&signer);
        if signer_balance < amount_to_deposit {
            return Err(TransactionError::InsufficientFunds);
        }

        // Process transfer
        token.transfer(&signer, &to, &amount_to_deposit);

        // Emit event
        e.events()
            .publish((symbol_short!("deposit"),), (signer, to, amount_to_deposit));

        Ok(())
    }
}
