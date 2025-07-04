use crate::datatypes::{DisputeDecision, Payment, PaymentEscrowError, PaymentStatus};
use soroban_sdk::{Address, Env, String, Vec};

pub trait PaymentEscrowInterface {
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

    fn get_payment(env: Env, payment_id: u128) -> Result<Payment, PaymentEscrowError>;

    // 2. Confirm delivery - releases funds to seller
    // fn confirm_delivery(env: Env, payment_id: u128, buyer: Address) -> Result<(), PaymentEscrowError>;

    // // 3. Dispute payment - locks funds in contract
    // fn dispute_payment(
    //     env: Env,
    //     payment_id: u64,
    //     disputer: Address,
    //     reason: String,
    // ) -> Result<(), PaymentEscrowError>;

    // // 4. Resolve dispute - arbitrator decides fund destination
    // fn resolve_dispute(
    //     env: Env,
    //     payment_id: u64,
    //     arbitrator: Address,
    //     decision: DisputeDecision,
    //     reason: String,
    // ) -> Result<(), PaymentEscrowError>;

    // // 5. Process expired payments - auto-refund
    // fn claim_expired_refund(env: Env, payment_id: u64) -> Result<(), PaymentEscrowError>;

    // // 6. Emergency release (seller can claim after dispute period)
    // fn claim_payment(env: Env, payment_id: u64, seller: Address) -> Result<(), PaymentEscrowError>;
}
