cat > StarShopContracts/governance-system-contract/src/types.rs << 'EOF'
use soroban_sdk::{Address, Bytes, Env, Symbol, Vec, symbol_short, contracterror};

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    // General errors
    AlreadyInitialized = 1,
    NotInitialized = 2,
    Unauthorized = 3,
    
    // Proposal errors
    ProposalNotFound = 101,
    InvalidProposalStatus = 102,
    NotEligibleToPropose = 103,
    ProposalInCooldown = 104,
    InsufficientStake = 105,
    InvalidProposalType = 106,
    ProposalLimitReached = 107,
    
    // Voting errors
    ProposalNotActive = 201,
    AlreadyVoted = 202,
    NoVotingPower = 203,
    InvalidVotingPeriod = 204,
    
    // Weight errors
    InvalidDelegation = 301,
    SelfDelegationNotAllowed = 302,
    
    // Execution errors
    ProposalNotExecutable = 401,
    ExecutionFailed = 402,
    ExecutionDelayNotMet = 403,
    InvalidAction = 404,
}

// Proposal status enum
#[derive(Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum ProposalStatus {
    Draft = 0,
    Active = 1,
    Passed = 2,
    Rejected = 3,
    Executed = 4,
    Canceled = 5,
}

// Proposal types
#[derive(Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum ProposalType {
    FeatureRequest = 0,
    PolicyChange = 1,
    ParameterChange = 2,
    ContractUpgrade = 3,
    EmergencyAction = 4,
}

// An action to be executed if a proposal passes
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Action {
    pub contract_id: Address,
    pub function: Symbol,
    pub args: Vec<Bytes>,
}

// Voting configuration
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VotingConfig {
    pub duration: u64,          // Duration in ledger timestamps
    pub quorum: i128,           // Minimum percentage of votes required (e.g. 4000 = 40%)
    pub threshold: i128,        // Minimum percentage of 'yes' votes to pass (e.g. 5100 = 51%)
    pub execution_delay: u64,   // Delay before execution (in ledger timestamps)
}

// Main proposal structure
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Proposal {
    pub id: u32,
    pub proposer: Address,
    pub title: Symbol,
    pub description: Symbol,
    pub proposal_type: ProposalType,
    pub status: ProposalStatus,
    pub created_at: u64,
    pub activated_at: u64,
    pub voting_config: VotingConfig,
    pub actions: Vec<Action>,
}

// Vote record
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Vote {
    pub voter: Address,
    pub support: bool,
    pub weight: i128,
    pub timestamp: u64,
}

// Public structures for moderation and anti-manipulation
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProposalRequirements {
    pub cooldown_period: u64,   // Time required between proposals from same address
    pub required_stake: i128,   // Tokens required to stake when proposing
    pub proposal_limit: u32,    // Max active proposals per address
}

// Vote weight tracking
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WeightSnapshot {
    pub proposal_id: u32,
    pub snapshot_at: u64,
}

// Constants for the contract
pub const ADMIN_KEY: Symbol = symbol_short!("ADMIN");
pub const PROPOSAL_COUNTER_KEY: Symbol = symbol_short!("PCNT");
pub const PROPOSAL_PREFIX: Symbol = symbol_short!("PROP");
pub const VOTE_PREFIX: Symbol = symbol_short!("VOTE");
pub const WEIGHT_PREFIX: Symbol = symbol_short!("WGHT");
pub const DELEGATE_PREFIX: Symbol = symbol_short!("DELG");
pub const SNAPSHOT_PREFIX: Symbol = symbol_short!("SNAP");
pub const REQUIREMENTS_KEY: Symbol = symbol_short!("REQS");
pub const TOKEN_KEY: Symbol = symbol_short!("TOKN");
pub const PROPOSAL_IDS_KEY: Symbol = symbol_short!("PIDS");
pub const PROPOSAL_STATUS_PREFIX: Symbol = symbol_short!("STAT");
