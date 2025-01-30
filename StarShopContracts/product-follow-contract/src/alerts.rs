use crate::datatype::{
    DataKeys, EventLog, FollowCategory, FollowData, FollowError, NotificationPriority,
};
use crate::interface::AlertOperations;
use soroban_sdk::{Address, Env, Vec};

pub struct AlertSystem;

impl AlertOperations for AlertSystem {
    fn check_price_change(env: Env, product_id: u128, new_price: u64) -> Result<(), FollowError> {
        // Get all users following this product
        let users = Self::get_users_following_product(&env, product_id)?;

        for user_address in users {
            let follow_key = DataKeys::FollowList(user_address.clone());
            let follows: Vec<FollowData> = env
                .storage()
                .persistent()
                .get(&follow_key)
                .unwrap_or_else(|| Vec::new(&env));

            // Check if user is following for price changes
            if let Some(follow) = follows.iter().find(|f| {
                f.product_id == product_id && f.categories.contains(&FollowCategory::PriceChange)
            }) {
                // Log the price change event
                let event = EventLog {
                    product_id,
                    event_type: FollowCategory::PriceChange,
                    triggered_at: env.ledger().timestamp(),
                    priority: NotificationPriority::High, // Price changes are high priority
                };

                Self::log_event(&env, user_address.clone(), event)?;
            }
        }

        Ok(())
    }

    fn check_restock(env: Env, product_id: u128) -> Result<(), FollowError> {
        let users = Self::get_users_following_product(&env, product_id)?;

        for user_address in users {
            let follow_key = DataKeys::FollowList(user_address.clone());
            let follows: Vec<FollowData> = env
                .storage()
                .persistent()
                .get(&follow_key)
                .unwrap_or_else(|| Vec::new(&env));

            if let Some(follow) = follows.iter().find(|f| {
                f.product_id == product_id && f.categories.contains(&FollowCategory::Restock)
            }) {
                let event = EventLog {
                    product_id,
                    event_type: FollowCategory::Restock,
                    triggered_at: env.ledger().timestamp(),
                    priority: NotificationPriority::Medium,
                };

                Self::log_event(&env, user_address.clone(), event)?;
            }
        }

        Ok(())
    }

    fn check_special_offer(env: Env, product_id: u128) -> Result<(), FollowError> {
        let users = Self::get_users_following_product(&env, product_id)?;

        for user_address in users {
            let follow_key = DataKeys::FollowList(user_address.clone());
            let follows: Vec<FollowData> = env
                .storage()
                .persistent()
                .get(&follow_key)
                .unwrap_or_else(|| Vec::new(&env));

            if let Some(follow) = follows.iter().find(|f| {
                f.product_id == product_id && f.categories.contains(&FollowCategory::SpecialOffer)
            }) {
                let event = EventLog {
                    product_id,
                    event_type: FollowCategory::SpecialOffer,
                    triggered_at: env.ledger().timestamp(),
                    priority: NotificationPriority::Low,
                };

                Self::log_event(&env, user_address.clone(), event)?;
            }
        }

        Ok(())
    }
}

impl AlertSystem {
    // Helper function to get all users following a specific product
    fn get_users_following_product(
        env: &Env,
        product_id: u128,
    ) -> Result<Vec<Address>, FollowError> {
        let mut following_users = Vec::new(env);

        // Get all users with follow lists
        let all_users_key = DataKeys::AllUsers;
        let all_users: Vec<Address> = env
            .storage()
            .persistent()
            .get(&all_users_key)
            .unwrap_or_else(|| Vec::new(env));

        // Iterate over all users and check their follow lists
        for user in all_users.iter() {
            let follow_list_key = DataKeys::FollowList(user.clone());
            if let Some(follows) = env
                .storage()
                .persistent()
                .get::<DataKeys, Vec<FollowData>>(&follow_list_key)
            {
                // Check if the user follows the product
                if follows.iter().any(|f| f.product_id == product_id) {
                    following_users.push_back(user.clone());
                }
            }
        }

        Ok(following_users)
    }

    // Helper function to log events
    fn log_event(env: &Env, user: Address, event: EventLog) -> Result<(), FollowError> {
        let history_key = DataKeys::NotificationHistory(user);
        let mut history: Vec<EventLog> = env
            .storage()
            .persistent()
            .get(&history_key)
            .unwrap_or_else(|| Vec::new(env));

        history.push_back(event);

        // Limit history size (optional)
        while history.len() > 100 {
            // Keep last 100 notifications
            history.remove(0);
        }

        env.storage().persistent().set(&history_key, &history);
        Ok(())
    }
}
