use crate::{
    datatypes::{DataKey, Payment, PaymentEscrowError, PaymentStatus, DisputeEvent, DisputeResolvedEvent, DisputeDecision},
    interface::DisputeInterface,
    PaymentEscrowContract, PaymentEscrowContractClient, PaymentEscrowContractArgs
};
use soroban_sdk::token::Client as TokenClient;
use soroban_sdk::{symbol_short, String, Address, Env, Vec, contractimpl};


#[contractimpl]
impl DisputeInterface for PaymentEscrowContract {

    fn dispute_payment(env: Env, payment_id: u128, disputer: Address, reason: String) -> Result<(), PaymentEscrowError> {
        // Authentication - disputer must authorize this transaction
        disputer.require_auth();

        // Get the payment from storage
        let payment: Payment = env
            .storage()
            .persistent()
            .get(&payment_id)
            .ok_or(PaymentEscrowError::NotFound)?;

        // Check if the disputer is either the buyer or seller
        if payment.buyer != disputer && payment.seller != disputer {
            return Err(PaymentEscrowError::UnauthorizedAccess);
        }

        // Check if payment has already been disputed
        if payment.status == PaymentStatus::Disputed {
            return Err(PaymentEscrowError::AlreadyDisputed);
        }

        // Check if payment is still in a disputable state (not completed or expired)
        if payment.status == PaymentStatus::Completed || payment.status == PaymentStatus::Expired {
            return Err(PaymentEscrowError::NotValid);
        }

        // Check if dispute period has expired
        let current_timestamp = env.ledger().timestamp();
        if current_timestamp > payment.dispute_deadline {
            return Err(PaymentEscrowError::DisputePeriodExpired);
        }

        // Create updated payment with Disputed status
        let updated_payment = Payment {
            status: PaymentStatus::Disputed,
            ..payment
        };

        // Store the updated payment
        env.storage()
            .persistent()
            .set(&payment_id, &updated_payment);

        // Create dispute event
        let dispute_event = DisputeEvent {
            order_id: payment_id,
            initiator: disputer,
            reason,
        };

        // Store dispute event
        env.storage()
            .persistent()
            .set(&(DataKey::DisputedPayments, payment_id), &dispute_event);

        // Publish event
        env.events().publish((symbol_short!("disputed"), payment_id), payment_id);

        Ok(())
    }

    fn resolve_dispute(env: Env, payment_id: u128, arbitrator: Address, decision: DisputeDecision, reason: String) -> Result<(), PaymentEscrowError> {
        // Authentication - arbitrator must authorize this transaction
        arbitrator.require_auth();

        // Get the payment from storage
        let payment: Payment = env
            .storage()
            .persistent()
            .get(&payment_id)
            .ok_or(PaymentEscrowError::NotFound)?;

        // Check if payment is in disputed status
        if payment.status != PaymentStatus::Disputed {
            return Err(PaymentEscrowError::NotValid);
        }

        // Check if the arbitrator is authorized
        let authorized_arbitrators: Vec<Address> = env
            .storage()
            .persistent()
            .get(&DataKey::Arbitrator)
            .ok_or(PaymentEscrowError::UnauthorizedAccess)?;

        if !authorized_arbitrators.contains(&arbitrator) {
            return Err(PaymentEscrowError::NotArbitrator);
        }

        // Validate reason is not empty
        if reason.is_empty() {
            return Err(PaymentEscrowError::NotValid);
        }

        // Create token client
        let token_client = TokenClient::new(&env, &payment.token);

        // Use match to settle dispute based on decision
        match decision {
            DisputeDecision::PaySeller => {
                // Transfer funds to seller
                let transfer_result = token_client.transfer(
                    &env.current_contract_address(),
                    &payment.seller,
                    &payment.amount,
                );
                if transfer_result != () {
                    return Err(PaymentEscrowError::TransferFailed);
                }

                // Update payment status to Completed
                let updated_payment = Payment {
                    status: PaymentStatus::Completed,
                    ..payment
                };
                env.storage()
                    .persistent()
                    .set(&payment_id, &updated_payment);
            },
            DisputeDecision::RefundBuyer => {
                // Transfer funds back to buyer
                let transfer_result = token_client.transfer(
                    &env.current_contract_address(),
                    &payment.buyer,
                    &payment.amount,
                );
                if transfer_result != () {
                    return Err(PaymentEscrowError::TransferFailed);
                }

                // Update payment status to Refunded
                let updated_payment = Payment {
                    status: PaymentStatus::Refunded,
                    ..payment
                };
                env.storage()
                    .persistent()
                    .set(&payment_id, &updated_payment);
            }
        }

        // Create dispute resolved event
        let dispute_resolved_event = DisputeResolvedEvent {
            order_id: payment_id,
            resolution: decision,
            admin: arbitrator,
        };

        // Store dispute resolved event
        env.storage()
            .persistent()
            .set(&(DataKey::ResolvedDisputes, payment_id), &dispute_resolved_event);

        // Publish event
        env.events().publish((symbol_short!("resolved"), payment_id), payment_id);

        Ok(())
    }
}