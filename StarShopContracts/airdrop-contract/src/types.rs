use soroban_sdk::{Address, Map, Symbol, contracterror, contracttype};

/// Represents an airdrop event with dynamic eligibility conditions.
#[contracttype]
pub struct AirdropEvent {
    /// Map of condition names to minimum required values (e.g., "purchases" -> 5).
    pub conditions: Map<Symbol, u64>,
    /// Amount of tokens to distribute to each eligible user.
    pub amount: u64,
    /// Address of the token contract (XLM or custom token).
    pub token_address: Address,
}

/// Represents a user's data with dynamic metrics.
#[contracttype]
pub struct UserData {
    /// Map of user metrics (e.g., "purchases" -> 10, "activity_points" -> 100).
    pub metrics: Map<Symbol, u64>,
}

/// Storage keys for persistent data in the contract.
#[contracttype]
pub enum DataKey {
    /// Key for the admin's address.
    Admin,
    /// Key for the current event ID counter.
    EventId,
    /// Key for an airdrop event, identified by its event ID.
    AirdropEvent(u64),
    /// Key to track if a user has claimed an airdrop, identified by event ID and user address.
    Claimed(u64, Address),
    /// Key for a user's data, identified by their address.
    UserData(Address),
}

/// Error codes for the airdrop contract.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum AirdropError {
    AlreadyInitialized = 1,
    Unauthorized = 2,
    InvalidTokenConfig = 3,
    AirdropNotFound = 4,
    UserNotEligible = 5,
    AlreadyClaimed = 6,
    InsufficientContractBalance = 7,
    TokenTransferFailed = 8,
    ConditionNotFound = 9,
    InvalidAmount = 10,
}
