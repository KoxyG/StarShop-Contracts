use soroban_sdk::{contracterror, contracttype, Address, Vec};

/// Categories for follow preferences
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FollowCategory {
    PriceChange,  // Notify on price updates
    Restock,      // Notify when restocked
    SpecialOffer, // Notify on special offers
}

/// Notification priority levels
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NotificationPriority {
    Low,
    Medium,
    High,
}

/// Storage keys for organizing contract data
#[derive(Clone)]
#[contracttype]
pub enum DataKeys {
    FollowList(Address),          // List of products a user follows
    FollowCategory(Address),      // Categories of follows per user
    AlertSettings(Address),       // User notification preferences
    NotificationHistory(Address), // Record of past notifications
    FollowLimit(Address),         // Max follow limit per user
    ExpirationTracker(Address),
    AllUsers, // Tracks follow expiration times
}

/// Error types for the follow system
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum FollowError {
    FollowLimitExceeded = 1, // User exceeded follow limit
    AlreadyFollowing = 2,    // Product already followed
    NotFollowing = 3,        // Cannot unfollow a non-followed product
    InvalidCategory = 4,     // Invalid follow category
    Unauthorized = 5,        // Unauthorized action
}

/// Data structure representing a followed product
#[contracttype]
#[derive(Clone)]
pub struct FollowData {
    pub product_id: u128,                // ID of the followed product
    pub categories: Vec<FollowCategory>, // Categories of interest
    pub timestamp: u64,                  // When the product was followed
    pub expires_at: Option<u64>,         // Optional expiration timestamp
}

/// User's follow preferences and settings
#[contracttype]
pub struct NotificationPreferences {
    pub user: Address,                   // User address
    pub categories: Vec<FollowCategory>, // Preferred categories
    pub mute_notifications: bool,        // Whether notifications are muted
    pub priority: NotificationPriority,  // Notification priority level
}

/// Tracks events before sending notifications
#[contracttype]
#[derive(Clone)]
pub struct EventLog {
    pub product_id: u128,               // Related product ID
    pub event_type: FollowCategory,     // Type of event
    pub triggered_at: u64,              // Timestamp when event occurred
    pub priority: NotificationPriority, // Priority level of notification
}
