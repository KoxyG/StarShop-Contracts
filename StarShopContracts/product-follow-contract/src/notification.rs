use crate::datatype::{
    DataKeys, EventLog, FollowCategory, FollowData, FollowError, NotificationPreferences,
    NotificationPriority,
};
use crate::interface::NotificationOperations;
use soroban_sdk::{Address, Env, Vec};

pub struct NotificationSystem;

impl NotificationOperations for NotificationSystem {
    fn set_notification_preferences(
        env: Env,
        user: Address,
        preferences: NotificationPreferences,
    ) -> Result<(), FollowError> {
        // Verify user authorization
        user.require_auth();

        // Validate user matches preferences
        if user != preferences.user {
            return Err(FollowError::Unauthorized);
        }

        // Validate categories
        for category in preferences.categories.iter() {
            match category {
                FollowCategory::PriceChange
                | FollowCategory::Restock
                | FollowCategory::SpecialOffer => continue,
            }
        }

        // Store preferences
        let prefs_key = DataKeys::AlertSettings(user.clone());
        env.storage().persistent().set(&prefs_key, &preferences);

        Ok(())
    }

    fn get_notification_preferences(
        env: Env,
        user: Address,
    ) -> Result<NotificationPreferences, FollowError> {
        let prefs_key = DataKeys::AlertSettings(user.clone());

        // Return default preferences if none are set
        let preferences = env
            .storage()
            .persistent()
            .get(&prefs_key)
            .unwrap_or_else(|| NotificationPreferences {
                user: user.clone(),
                categories: Vec::from_array(
                    &env,
                    [
                        FollowCategory::PriceChange,
                        FollowCategory::Restock,
                        FollowCategory::SpecialOffer,
                    ],
                ),
                mute_notifications: false,
                priority: NotificationPriority::Medium,
            });

        Ok(preferences)
    }

    fn log_event(env: Env, event: EventLog) -> Result<(), FollowError> {
        // Get all users following this product
        let users = Self::get_users_for_event(&env, &event)?;

        for user in users.iter() {
            // Check user preferences
            let preferences = Self::get_notification_preferences(env.clone(), user.clone())?;

            // Skip if notifications are muted or category is not preferred
            if preferences.mute_notifications || !preferences.categories.contains(&event.event_type)
            {
                continue;
            }

            // Store event in user's notification history
            let history_key = DataKeys::NotificationHistory(user.clone());
            let mut history: Vec<EventLog> = env
                .storage()
                .persistent()
                .get(&history_key)
                .unwrap_or_else(|| Vec::new(&env));

            // Add new event with user's preferred priority
            let mut user_event = event.clone();
            user_event.priority = preferences.priority;
            history.push_back(user_event);

            // Maintain history size limit (keep last 100 notifications)
            while history.len() > 100 {
                history.remove(0);
            }

            env.storage().persistent().set(&history_key, &history);
        }

        Ok(())
    }

    fn get_notification_history(env: Env, user: Address) -> Result<Vec<EventLog>, FollowError> {
        let history_key = DataKeys::NotificationHistory(user.clone());
        let history: Vec<EventLog> = env
            .storage()
            .persistent()
            .get(&history_key)
            .unwrap_or_else(|| Vec::new(&env));

        Ok(history)
    }
}

impl NotificationSystem {
    // Helper function to get users who should receive an event notification
    fn get_users_for_event(env: &Env, event: &EventLog) -> Result<Vec<Address>, FollowError> {
        let mut target_users = Vec::new(env);

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
                // Check if the user follows the product and relevant category
                if follows.iter().any(|f| {
                    f.product_id == event.product_id && f.categories.contains(&event.event_type)
                }) {
                    target_users.push_back(user.clone());
                }
            }
        }
        Ok(target_users)
    }
}
