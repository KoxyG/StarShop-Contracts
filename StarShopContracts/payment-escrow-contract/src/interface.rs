use crate::datatypes::{DisputeDecision, Payment, PaymentEscrowError};
use soroban_sdk::{Address, Env, String, Vec};

pub trait PaymentInterface {
    fn get_payment_count(env: &Env) -> u128 ;

    fn create_payment(
        env: Env,
        buyer: Address,
        seller: Address,
        amount: i128,
        token: Address,
        expiry_days: u32,
        description: String,
    ) -> Result<u128, PaymentEscrowError>;

    fn get_a_payment(env: Env, payment_id: u128) -> Result<Payment, PaymentEscrowError>;
}

pub trait DeliveryInterface {
 // 2. Confirm delivery - releases funds to seller
 fn buyer_confirm_delivery(env: Env, payment_id: u128, buyer: Address) -> Result<(), PaymentEscrowError>;

 fn seller_confirm_delivery(env: Env, payment_id: u128, seller: Address) -> Result<(), PaymentEscrowError>;

//  fn get_delivery_status(env: Env, payment_id: u128) -> Result<PaymentStatus, PaymentEscrowError>;

//  fn get_delivery_details(env: Env, payment_id: u128) -> Result<DeliveryDetails, PaymentEscrowError>;
}

pub trait DisputeInterface {
    fn dispute_payment(env: Env, payment_id: u128, disputer: Address, reason: String) -> Result<(), PaymentEscrowError>;
    fn resolve_dispute(env: Env, payment_id: u128, arbitrator: Address, decision: DisputeDecision, reason: String) -> Result<(), PaymentEscrowError>;
}


pub trait ClaimInterface {
    fn claim_payment(env: Env, payment_id: u128, claimer: Address) -> Result<(), PaymentEscrowError>;
}


pub trait ArbitratorInterface {
    fn add_arbitrator(env: Env, arbitrator: Address) -> Result<(), PaymentEscrowError>;
    fn remove_arbitrator(env: Env, arbitrator: Address) -> Result<(), PaymentEscrowError>;
    fn get_arbitrators(env: Env) -> Result<Vec<Address>, PaymentEscrowError>;
    fn transfer_arbitrator_rights(env: Env, old_arbitrator: Address, new_arbitrator: Address) -> Result<(), PaymentEscrowError>;
}