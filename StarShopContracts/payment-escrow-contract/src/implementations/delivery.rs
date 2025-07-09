use crate::{
    datatypes::{DeliveryDetails, Payment, PaymentEscrowError, PaymentStatus},
    interface::DeliveryInterface,
    PaymentEscrowContract, PaymentEscrowContractArgs, PaymentEscrowContractClient,
};
use soroban_sdk::token::Client as TokenClient;
use soroban_sdk::{contractimpl, symbol_short, Address, Env};

#[contractimpl]
impl DeliveryInterface for PaymentEscrowContract {
    fn buyer_confirm_delivery(
        env: Env,
        payment_id: u128,
        buyer: Address,
    ) -> Result<(), PaymentEscrowError> {
        // Authentication - buyer must authorize this transaction
        buyer.require_auth();

        // Get the payment from storage
        let payment: Payment = env
            .storage()
            .persistent()
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

         // Can't confirm a payment that is disputed
         if payment.status == PaymentStatus::Disputed {
            return Err(PaymentEscrowError::PaymentDisputed);
        }


        // Transfer funds to seller
        let token_client = TokenClient::new(&env, &payment.token);

        token_client.transfer(
            &env.current_contract_address(),
            &payment.seller,
            &payment.amount,
        );

        // Create updated payment with Completed status
        let updated_payment = Payment {
            status: PaymentStatus::Completed,
            ..payment
        };

        // Store the updated payment
        env.storage()
            .persistent()
            .set(&payment_id, &updated_payment);

        // Publish event
        env.events()
            .publish((symbol_short!("completed"), payment_id), payment_id);

        Ok(())
    }

    fn seller_confirm_delivery(
        env: Env,
        payment_id: u128,
        seller: Address,
    ) -> Result<(), PaymentEscrowError> {
        // Authentication - seller must authorize this transaction
        seller.require_auth();

        // Get the payment from storage
        let payment: Payment = env
            .storage()
            .persistent()
            .get(&payment_id)
            .ok_or(PaymentEscrowError::NotFound)?;

        // Check if payment is in correct status
        if payment.status != PaymentStatus::Pending {
            return Err(PaymentEscrowError::NotValid);
        }

        // Can't confirm a payment that is disputed
        if payment.status == PaymentStatus::Disputed {
            return Err(PaymentEscrowError::PaymentDisputed);
        }

        // Create updated payment with Delivered status

        // Check if the caller is actually the seller
        if payment.seller != seller {
            return Err(PaymentEscrowError::UnauthorizedAccess);
        }

        // Create updated payment with Delivered status
        let updated_payment = Payment {
            status: PaymentStatus::Delivered,
            ..payment
        };

        // Store the updated payment
        env.storage()
            .persistent()
            .set(&payment_id, &updated_payment);

        // Publish event
        env.events()
            .publish((symbol_short!("delivered"), payment_id), payment_id);

        Ok(())
    }

    fn get_delivery_status(
        env: Env,
        payment_id: u128,
    ) -> Result<PaymentStatus, PaymentEscrowError> {
        // Get the payment from storage
        let payment: Payment = env
            .storage()
            .persistent()
            .get(&payment_id)
            .ok_or(PaymentEscrowError::NotFound)?;

        // Return the payment status
        Ok(payment.status)
    }

    fn get_delivery_details(
        env: Env,
        payment_id: u128,
    ) -> Result<DeliveryDetails, PaymentEscrowError> {
        // Get the payment from storage
        let payment: Payment = env
            .storage()
            .persistent()
            .get(&payment_id)
            .ok_or(PaymentEscrowError::NotFound)?;

        // Create and return delivery details
        let delivery_details = DeliveryDetails {
            payment_id,
            buyer: payment.buyer,
            seller: payment.seller,
            status: payment.status,
            created_at: payment.created_at,
            expiry: payment.expiry,
            description: payment.description,
        };

        Ok(delivery_details)
    }
}
