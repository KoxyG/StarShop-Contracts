use crate::{
    datatypes::{Payment, PaymentEscrowError, PaymentStatus},
    interface::DeliveryInterface,
    PaymentEscrowContract, PaymentEscrowContractClient, PaymentEscrowContractArgs
};
use soroban_sdk::token::Client as TokenClient;
use soroban_sdk::{contractimpl, symbol_short, Address, Env};


#[contractimpl]
impl DeliveryInterface for PaymentEscrowContract {
    fn buyer_confirm_delivery(env: Env, payment_id: u128, buyer: Address) -> Result<(), PaymentEscrowError> {
        // Authentication - buyer must authorize this transaction
        buyer.require_auth();

        // Get the payment from storage
        let payment: Payment = env
            .storage()
            .instance()
            .get(&payment_id)
            .ok_or(PaymentEscrowError::NotFound)?;

        // Check if the caller is actually the buyer
        if payment.buyer != buyer {
            return Err(PaymentEscrowError::UnauthorizedAccess);
        }

        // Check if payment status is Delivered (not Pending)
        if payment.status != PaymentStatus::Delivered {
            return Err(PaymentEscrowError::NotDelivered);
        }

        // Create updated payment with Completed status
        let updated_payment = Payment {
            status: PaymentStatus::Completed,
            ..payment
        };

        // Store the updated payment
        env.storage()
            .instance()
            .set(&payment_id, &updated_payment);

        

        // Publish event
        env.events().publish((symbol_short!("completed"), payment_id), payment_id);

        Ok(())
    }

    fn seller_confirm_delivery(env: Env, payment_id: u128, seller: Address) -> Result<(), PaymentEscrowError> {
        // Authentication - seller must authorize this transaction
        seller.require_auth();

        // Get the payment from storage
        let payment: Payment = env
            .storage()
            .instance()
            .get(&payment_id)
            .ok_or(PaymentEscrowError::NotFound)?;

        // Check if the caller is actually the seller
        if payment.seller != seller {
            return Err(PaymentEscrowError::UnauthorizedAccess);
        }

        // Check if payment status is Pending
        if payment.status != PaymentStatus::Pending {
            return Err(PaymentEscrowError::NotValid);
        }

        // Create updated payment with Delivered status
        let updated_payment = Payment {
            status: PaymentStatus::Delivered,
            ..payment
        };

        // Store the updated payment
        env.storage()
            .instance()
            .set(&payment_id, &updated_payment);

        // Transfer funds to seller
        let token_client = TokenClient::new(&env, &updated_payment.token);

        let transfer_result =
            token_client.transfer(&env.current_contract_address(),  &updated_payment.seller,
            &updated_payment.amount,);
        if transfer_result != () {
            return Err(PaymentEscrowError::TransferFailed);
        }

        // Publish event
        env.events().publish((symbol_short!("delivered"), payment_id), payment_id);

        Ok(())
    }
}