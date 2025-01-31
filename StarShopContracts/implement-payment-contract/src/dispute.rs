use soroban_sdk::token::Client as TokenClient;
use soroban_sdk::{
    contract, contracterror, contractimpl, symbol_short, Address, ConversionError, Env, IntoVal,
    TryFromVal, TryIntoVal, Val,
};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum DisputeDecision {
    RefundBuyer = 0,
    PaySeller = 1,
}

impl TryFromVal<Env, Val> for DisputeDecision {
    type Error = ConversionError;

    fn try_from_val(env: &Env, val: &Val) -> Result<Self, Self::Error> {
        let val: u32 = val.try_into_val(env)?;
        match val {
            0 => Ok(DisputeDecision::RefundBuyer),
            1 => Ok(DisputeDecision::PaySeller),
            _ => Err(ConversionError),
        }
    }
}

impl IntoVal<Env, Val> for DisputeDecision {
    fn into_val(&self, env: &Env) -> Val {
        (*self as u32).into_val(env)
    }
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum DisputeError {
    InsufficientFunds = 1,
    TransferFailed = 2,
    InvalidAmount = 3,
    UnauthorizedAccess = 4,
}

#[contract]
pub struct DisputeContract;

#[contractimpl]
impl DisputeContract {
    pub fn resolve_dispute(
        e: Env,
        token_id: Address,
        arbitrator: Address,
        buyer: Address,
        seller: Address,
        refund_amount: i128,
        decision: DisputeDecision,
    ) -> Result<(), DisputeError> {
        // Check authorization
        arbitrator.require_auth();

        // Input validations
        if refund_amount <= 0 {
            return Err(DisputeError::InvalidAmount);
        }

        let token = TokenClient::new(&e, &token_id);

        // Check balance
        let arbitrator_balance = token.balance(&arbitrator);
        if arbitrator_balance < refund_amount {
            return Err(DisputeError::InsufficientFunds);
        }

        // Process transfer based on decision
        match decision {
            DisputeDecision::RefundBuyer => {
                token.transfer(&arbitrator, &buyer, &refund_amount);
            }
            DisputeDecision::PaySeller => {
                token.transfer(&arbitrator, &seller, &refund_amount);
            }
        }

        // Emit event
        e.events().publish(
            (symbol_short!("dispute"),),
            (arbitrator, buyer, seller, refund_amount, decision as u32),
        );

        Ok(())
    }
}
