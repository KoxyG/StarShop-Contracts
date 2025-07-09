use crate::{
    datatypes::{Payment, PaymentEscrowError, PaymentStatus},
    interface::ClaimInterface,
    PaymentEscrowContract, PaymentEscrowContractClient, PaymentEscrowContractArgs
};
use soroban_sdk::token::Client as TokenClient;
use soroban_sdk::{contractimpl, symbol_short, Address, Env};


#[contractimpl]
impl ClaimInterface for PaymentEscrowContract {
    fn claim_payment(env: Env, payment_id: u128, claimer: Address) -> Result<(), PaymentEscrowError> {
        // Authentication - claimer must authorize this transaction
        claimer.require_auth();

        // Get the payment from storage
        let payment: Payment = env
            .storage()
            .persistent()
            .get(&payment_id)
            .ok_or(PaymentEscrowError::NotFound)?;

        // Check if the payment is expired
        let current_timestamp = env.ledger().timestamp();
        if current_timestamp <= payment.expiry {
            return Err(PaymentEscrowError::NotExpired);
        }

        // Can't claim a payment that is disputed
        if payment.status == PaymentStatus::Disputed {
            return Err(PaymentEscrowError::PaymentDisputed);
        }

        // Check if the caller is the buyer (buyer can claim expired payments)
        if payment.buyer != claimer {
            return Err(PaymentEscrowError::UnauthorizedAccess);
        }

        // Create token client
        let token_client = TokenClient::new(&env, &payment.token);

        token_client.transfer(&env.current_contract_address(), &payment.buyer,
            &payment.amount);

        // Update payment status to Refunded
        let updated_payment = Payment {
            status: PaymentStatus::Refunded,
            ..payment
        };
        env.storage()
            .persistent()
            .set(&payment_id, &updated_payment);

        // Publish event
        env.events().publish((symbol_short!("claimed"), payment_id), payment_id);

        Ok(())
    }
}