use crate::types::{AirdropError, AirdropEvent, DataKey};
use soroban_sdk::{Address, Env, Symbol, token};

pub struct DistributionManager<'a> {
    env: &'a Env,
}

impl<'a> DistributionManager<'a> {
    /// Creates a new DistributionManager instance.
    pub fn new(env: &'a Env) -> Self {
        Self { env }
    }

    /// Transfers tokens from the contract to a user.
    fn transfer_tokens(
        &self,
        token_address: &Address,
        to: &Address,
        amount: u64,
    ) -> Result<(), AirdropError> {
        let token_client = token::TokenClient::new(self.env, token_address);
        let contract_balance = token_client.balance(&self.env.current_contract_address());
        if contract_balance < amount as i128 {
            return Err(AirdropError::InsufficientContractBalance);
        }
        token_client.transfer(&self.env.current_contract_address(), to, &(amount as i128));
        Ok(())
    }

    /// Distributes tokens to a user for a specific airdrop event.
    ///
    /// # Arguments
    /// * `user` - The address of the user claiming the airdrop.
    /// * `event_id` - The ID of the airdrop event.
    ///
    /// # Returns
    /// * `Ok(())` on success.
    /// * `Err(AirdropError)` if the operation fails (e.g., airdrop not found, already claimed).
    pub fn distribute_tokens(&self, user: &Address, event_id: u64) -> Result<(), AirdropError> {
        // Require authentication from the user
        user.require_auth();

        // Retrieve the airdrop event
        let airdrop_event: AirdropEvent = self
            .env
            .storage()
            .persistent()
            .get(&DataKey::AirdropEvent(event_id))
            .ok_or(AirdropError::AirdropNotFound)?;

        // Check if the user has already claimed
        let claimed_key = DataKey::Claimed(event_id, user.clone());
        if self
            .env
            .storage()
            .persistent()
            .get(&claimed_key)
            .unwrap_or(false)
        {
            return Err(AirdropError::AlreadyClaimed);
        }

        // Validate amount
        if airdrop_event.amount <= 0 {
            return Err(AirdropError::InvalidAmount);
        }

        // Mark the user as having claimed
        self.env.storage().persistent().set(&claimed_key, &true);

        // Distribute tokens
        self.transfer_tokens(&airdrop_event.token_address, user, airdrop_event.amount)?;

        // Emit detailed event for transparency
        self.env.events().publish(
            ("claimed", event_id, user.clone()),
            (airdrop_event.token_address.clone(), airdrop_event.amount),
        );

        Ok(())
    }
}
