use crate::types::{AirdropError, DataKey, UserData};
use soroban_sdk::{Address, Env, Map, Symbol, contracterror};

pub struct AirdropManager<'a> {
    env: &'a Env,
}

impl<'a> AirdropManager<'a> {
    /// Creates a new AirdropManager instance.
    pub fn new(env: &'a Env) -> Self {
        Self { env }
    }

    /// Updates a user's metrics in storage.
    ///
    /// # Arguments
    /// * `caller` - The address of the caller (must be admin).
    /// * `user` - The address of the user whose data is being updated.
    /// * `metrics` - Map of metric names to values to update.
    ///
    /// # Returns
    /// * `Ok(())` on success.
    /// * `Err(AirdropError)` if unauthorized.
    pub fn update_user_data(
        &self,
        caller: &Address,
        user: &Address,
        metrics: Map<Symbol, u64>,
    ) -> Result<(), AirdropError> {
        // Verify caller is admin
        let admin: Address = self
            .env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .ok_or(AirdropError::Unauthorized)?;
        if *caller != admin {
            return Err(AirdropError::Unauthorized);
        }

        // Require caller authentication
        caller.require_auth();

        // Retrieve current user data or default
        let mut user_data = self.get_user_data(user);

        // Update metrics
        for (key, value) in metrics.iter() {
            user_data.metrics.set(key, value);
        }

        // Store updated data
        self.env
            .storage()
            .persistent()
            .set(&DataKey::UserData(user.clone()), &user_data);

        Ok(())
    }

    /// Retrieves a user's data from storage.
    ///
    /// # Arguments
    /// * `user` - The address of the user.
    ///
    /// # Returns
    /// * `UserData` for the user, or default if none exists.
    pub fn get_user_data(&self, user: &Address) -> UserData {
        self.env
            .storage()
            .persistent()
            .get(&DataKey::UserData(user.clone()))
            .unwrap_or(UserData {
                metrics: Map::new(self.env),
            })
    }
}
