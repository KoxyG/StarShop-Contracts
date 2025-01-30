use soroban_sdk::{contract, contractimpl, Address, Env, symbol_short, contracterror};
use soroban_sdk::token::Client as TokenClient;

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum RefundError {
    InsufficientFunds = 1,
    TransferFailed = 2,
    InvalidAmount = 3,
    UnauthorizedAccess = 4,
}

#[contract]
pub struct RefundContract;

#[contractimpl]
impl RefundContract {
    pub fn process_refund(
        e: Env,
        token_id: Address,
        signer: Address,
        to: Address,
        refund_amount: i128
    ) -> Result<(), RefundError> {
        // Check authorization
        signer.require_auth();

        // Input validations
        if refund_amount <= 0 {
            return Err(RefundError::InvalidAmount);
        }

        if signer == to {
            return Err(RefundError::UnauthorizedAccess);
        }

        let token = TokenClient::new(&e, &token_id);

        // Check balance
        let signer_balance = token.balance(&signer);
        if signer_balance < refund_amount {
            return Err(RefundError::InsufficientFunds);
        }

        // Process transfer
        token.transfer(&signer, &to, &refund_amount);

        // Emit event
        e.events().publish(
            (symbol_short!("refund"),),
            (signer, to, refund_amount),
        );

        Ok(())
    }
}
