use soroban_sdk::{contracterror, contracttype, Address, String, Vec};

/// User verification status in the system
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VerificationStatus {
    Pending,          // Initial state when verification is submitted
    Verified,         // User has passed verification
    Rejected(String), // User was rejected with reason
}

/// User levels with increasing benefits
/// Higher levels require stricter criteria and offer better rewards
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum UserLevel {
    Basic = 0,    // New users, basic commission rates
    Silver = 1,   // Intermediate level, improved rates
    Gold = 2,     // Advanced level, premium rates
    Platinum = 3, // Highest level, maximum benefits
}

/// Core user data structure containing all user-related information
#[contracttype]
#[derive(Clone)]
pub struct UserData {
    pub address: Address,                        // User's blockchain address
    pub referrer: Option<Address>,               // Address of user's referrer
    pub direct_referrals: Vec<Address>,          // List of direct referrals
    pub team_size: u32,                          // Total team size (all levels)
    pub pending_rewards: i128,                   // Unclaimed rewards
    pub total_rewards: i128,                     // All-time earned rewards
    pub level: UserLevel,                        // Current user level
    pub verification_status: VerificationStatus, // KYC status
    pub identity_proof: String,                  // Verification documents hash
    pub join_date: u64,                          // Registration timestamp
}

/// Milestone achievement criteria and rewards
#[contracttype]
#[derive(Clone)]
pub struct Milestone {
    pub required_level: UserLevel,         // Minimum level required
    pub requirement: MilestoneRequirement, // Achievement criteria
    pub reward_amount: i128,               // Reward for completion
    pub description: String,               // Milestone description
}

/// Different types of milestone requirements
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MilestoneRequirement {
    DirectReferrals(u32), // Number of direct referrals needed
    TeamSize(u32),        // Total team size required
    TotalRewards(i128),   // Cumulative rewards threshold
    ActiveDays(u64),      // Days of activity required
}

/// Storage keys for contract data
#[contracttype]
pub enum DataKey {
    Admin,                              // Contract administrator
    TotalUsers,                         // Total registered users
    RewardToken,                        // Token used for rewards
    RewardRates,                        // Commission rates config
    User(Address),                      // User data storage
    Milestone(u32),                     // Milestone data
    ContractPaused,                     // Contract pause status
    TotalDistributedRewards,            // Total rewards given
    UserAchievedMilestones(Address),    // User's completed milestones
    PendingVerifications(Vec<Address>), // Users awaiting verification
    LevelRequirements,                  // Level upgrade criteria
}

/// Commission rates for different referral levels
#[contracttype]
#[derive(Clone)]
pub struct RewardRates {
    pub level1: u32,                   // Direct referral rate (basis points)
    pub level2: u32,                   // Second level rate
    pub level3: u32,                   // Third level rate
    pub max_reward_per_referral: i128, // Maximum reward cap
}

/// Criteria for level upgrades
#[contracttype]
#[derive(Clone)]
pub struct LevelCriteria {
    pub required_direct_referrals: u32, // Minimum direct referrals
    pub required_team_size: u32,        // Minimum total team size
    pub required_total_rewards: i128,   // Minimum earned rewards
}

/// Requirements for each level upgrade
#[contracttype]
pub struct LevelRequirements {
    pub silver: LevelCriteria,   // Requirements for Silver
    pub gold: LevelCriteria,     // Requirements for Gold
    pub platinum: LevelCriteria, // Requirements for Platinum
}

/// Contract error types
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    NotInitialized = 1,            // Contract not initialized
    AlreadyInitialized = 2,        // Contract already setup
    Unauthorized = 3,              // Caller lacks permission
    AlreadyRegistered = 4,         // User already exists
    UserNotFound = 5,              // User doesn't exist
    MilestoneNotFound = 6,         // Milestone not found
    InvalidAmount = 7,             // Invalid reward amount
    VerificationRequired = 8,      // Action needs verification
    AlreadyVerified = 9,           // Already verified
    InvalidIdentityProof = 10,     // Invalid KYC documents
    InsufficientRewards = 11,      // Not enough rewards
    InvalidRewardRates = 12,       // Invalid commission rates
    MaxRewardExceeded = 13,        // Reward cap reached
    ReferrerNotVerified = 14,      // Referrer needs verification
    ReferrerNotFound = 15,         // Referrer doesn't exist
    InvalidLevelRequirements = 16, // Invalid level criteria
    ContractPaused = 17,           // Contract is paused
    InvalidRewardToken = 18,       // Invalid token address
}
