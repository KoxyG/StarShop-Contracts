use soroban_sdk::{contracterror, contracttype, symbol_short, Address, Bytes, Symbol, Vec};

#[contracttype]
#[derive(Clone, PartialEq)]
pub enum ProposalStatus {
    Draft = 0,
    Active = 1,
    Passed = 2,
    Rejected = 3,
    Executed = 4,
    Canceled = 5,
}

#[contracttype]
#[derive(Clone, PartialEq)]
pub enum ProposalType {
    FeatureRequest = 0,
    PolicyChange = 1,
    ParameterChange = 2,
    ContractUpgrade = 3,
    EmergencyAction = 4,
}

#[contracttype]
#[derive(Clone)]
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

#[contracttype]
#[derive(Clone)]
pub struct ProposalRequirements {
    pub cooldown_period: u64,
    pub required_stake: i128,
    pub proposal_limit: u32,
}

#[contracttype]
#[derive(Clone)]
pub struct Vote {
    pub voter: Address,
    pub support: bool,
    pub weight: i128,
    pub timestamp: u64,
}

#[contracttype]
#[derive(Clone)]
pub struct VotingConfig {
    pub duration: u64,
    pub quorum: i128,
    pub threshold: i128,
    pub execution_delay: u64,
}

#[contracttype]
#[derive(Clone)]
pub struct WeightSnapshot {
    pub proposal_id: u32,
    pub snapshot_at: u64,
}

#[contracttype]
#[derive(Clone)]
pub struct Action {
    pub contract_id: Address,
    pub function: Symbol,
    pub args: Vec<Bytes>,
}

// Custom Errors
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    // Initialization Errors
    AlreadyInitialized = 1,
    NotInitialized = 2,
    Unauthorized = 3,
    ProposalNotFound = 101,
    InvalidProposalStatus = 102,
    NotEligibleToPropose = 103,
    ProposalInCooldown = 104,
    InsufficientStake = 105,
    InvalidProposalType = 106,
    ProposalLimitReached = 107,
    // Proposal Voting Errors
    ProposalNotActive = 201,
    AlreadyVoted = 202,
    NoVotingPower = 203,
    InvalidVotingPeriod = 204,
    // Delegation Errors
    InvalidDelegation = 301,
    SelfDelegationNotAllowed = 302,
    // Execution Errors
    ProposalNotExecutable = 401,
    ExecutionFailed = 402,
    ExecutionDelayNotMet = 403,
    InvalidAction = 404,
}

// Constants
pub const ADMIN_KEY: Symbol = symbol_short!("ADMIN");
pub const PROPOSAL_COUNTER_KEY: Symbol = symbol_short!("PCNT");
pub const REQUIREMENTS_KEY: Symbol = symbol_short!("REQS");
pub const TOKEN_KEY: Symbol = symbol_short!("TOKN");
pub const DELEGATE_PREFIX: Symbol = symbol_short!("DELG");
pub const PROPOSAL_PREFIX: Symbol = symbol_short!("PROP");
pub const PROPOSAL_STATUS_PREFIX: Symbol = symbol_short!("STAT");
pub const SNAPSHOT_PREFIX: Symbol = symbol_short!("SNAP");
pub const VOTE_PREFIX: Symbol = symbol_short!("VOTE");
pub const WEIGHT_PREFIX: Symbol = symbol_short!("WGHT");
