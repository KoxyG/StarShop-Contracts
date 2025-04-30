use soroban_sdk::{contracttype, Address, String};

#[contracttype]
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct Auction {
    pub id: u32,
    pub owner: Address,
    pub item_metadata: ItemMetadata,
    pub start_time: u64,
    pub auction_conditions: AuctionConditions,
    pub curr_bid_amount: Option<i128>,
    pub curr_bidder: Option<Address>,
    pub no_of_bids: u32,
    pub no_of_participants: u32,
    pub last_bid_time: u64,
    pub token: Address,
    pub auction_status: AuctionStatus,
}

#[contracttype]
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct Bid {
    pub id: u32,
    pub bidder: Address,
    pub bid_amount: i128,
}

// Extendable Metadata to pass any required information
#[contracttype]
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct ItemMetadata {
    pub title: String,
    pub description: String,
}

#[contracttype]
#[derive(Clone, Eq, PartialEq, Debug)]
pub enum AuctionType {
    Regular,
    Reverse,
    Dutch(DutchAuctionData),
}

#[contracttype]
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct DutchAuctionData {
    pub floor_price: i128,
}

#[contracttype]
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct AuctionConditions {
    pub auction_type: AuctionType, // Auction Type (Regular, Reverse, Dutch)
    pub end_time: u64,             // Auction End Time
    pub starting_price: i128,      // Auction Starting Price

    // Auto-Close Conditions
    pub on_bid_count: Option<u32>,             // Close after X bids
    pub on_target_price: Option<i128>,         // Close if someone bids this price
    pub on_inactivity_seconds: Option<u64>,    // Close if no bids in X seconds
    pub on_fixed_sequence_number: Option<u32>, // Close at a specific ledger sequence number
    pub on_minimum_participants: Option<u32>,  // Close after X unique bidders
    pub on_maximum_participants: Option<u32>,  // Stop auction after X unique bidders
}

#[contracttype]
#[derive(Clone, Eq, PartialEq, Debug)]
pub enum AuctionStatus {
    Active,
    Cancelled,
    Completed,
}
