use crate::datatype::{EventLog, FollowCategory, FollowData, FollowError, NotificationPreferences};
use soroban_sdk::{Address, Env, Vec};

/// Handles product follow operations
pub trait FollowOperations {
    /// Allows a user to follow a product with specific categories
    fn follow_product(
        env: Env,
        user: Address,
        product_id: u128,
        categories: Vec<FollowCategory>,
    ) -> Result<(), FollowError>;

    /// Allows a user to unfollow a product
    fn unfollow_product(env: Env, user: Address, product_id: u128) -> Result<(), FollowError>;

    /// Retrieves the list of followed products for a user
    fn get_followed_products(env: Env, user: Address) -> Result<Vec<FollowData>, FollowError>;
}

/// Manages alert triggers for followed products
pub trait AlertOperations {
    /// Checks for price changes and triggers notifications
    fn check_price_change(env: Env, product_id: u128, new_price: u64) -> Result<(), FollowError>;

    /// Handles restock notifications
    fn check_restock(env: Env, product_id: u128) -> Result<(), FollowError>;

    /// Triggers special offer alerts
    fn check_special_offer(env: Env, product_id: u128) -> Result<(), FollowError>;
}

/// Handles notification preferences and history
pub trait NotificationOperations {
    /// Sets user notification preferences
    fn set_notification_preferences(
        env: Env,
        user: Address,
        preferences: NotificationPreferences,
    ) -> Result<(), FollowError>;

    /// Retrieves user notification preferences
    fn get_notification_preferences(
        env: Env,
        user: Address,
    ) -> Result<NotificationPreferences, FollowError>;

    /// Logs an event before sending a notification
    fn log_event(env: Env, event: EventLog) -> Result<(), FollowError>;

    /// Retrieves notification history
    fn get_notification_history(env: Env, user: Address) -> Result<Vec<EventLog>, FollowError>;
}
