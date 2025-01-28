use soroban_sdk::{contracterror, Address, Map, Symbol};

#[derive(Clone, Copy)]
#[repr(u32)]
pub enum VoteType {
    Upvote = 1,
    Downvote = 2,
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    VotingPeriodEnded = 1,
    AlreadyVoted = 2,
    ReversalWindowExpired = 3,
    DailyLimitReached = 4,
    AccountTooNew = 5,
    ProductNotFound = 6,
    ProductExists = 7,
}

pub struct Product {
    pub id: Symbol,
    pub name: Symbol,
    pub created_at: u64,
    pub votes: Map<Address, Vote>,
}

pub struct Vote {
    pub vote_type: VoteType,
    pub timestamp: u64,
    pub voter: Address,
}