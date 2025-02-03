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
    ExpirationTracker(Address),   // Tracks follow expiration times
    LastNotification(Address),    // Last notification timestamp
    AllUsers,
    ProductFollowers(u32), // List of followers for a product
}

/// Error types for the follow system
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum FollowError {
    FollowLimitExceeded = 1,
    AlreadyFollowing = 2,
    NotFollowing = 3,
    InvalidCategory = 4,
    Unauthorized = 5,
    InvalidProductId = 6,
}

/// Data structure representing a followed product
#[contracttype]
#[derive(Clone)]
pub struct FollowData {
    pub user: Address,
    pub product_id: u32,
    pub categories: Vec<FollowCategory>,
    pub timestamp: u64,
    pub expires_at: Option<u64>,
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

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum Error {
    AlreadyFollowing = 1,
    NotFollowing = 2,
    InvalidProduct = 3,
    NotificationFailed = 4,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AlertType {
    PriceChange,
    StockUpdate,
    ProductUpdate,
    Promotion,
}
