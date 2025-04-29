use soroban_sdk::{contracttype, symbol_short, Address, Symbol};

// Symbol representing GAME events.
pub const AUCTION: Symbol = symbol_short!("AUCTION");

// Symbol representing ADD events.
pub const CREATE: Symbol = symbol_short!("CREATE");

// Symbol representing ADD events.
pub const CANCEL: Symbol = symbol_short!("CANCEL");

// Symbol representing ADD events.
pub const END: Symbol = symbol_short!("END");

// Symbol representing Vote events.
pub const BID: Symbol = symbol_short!("BID");

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuctionCreated {
    pub auction_id: u32,
    pub owner: Address,
    pub start_time: u64,
    pub end_time: u64,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NewBidPlaced {
    pub auction_id: u32,
    pub bidder: Address,
    pub bid_amount: i128,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuctionCanceled {
    pub auction_id: u32,
    pub owner: Address,
    pub timestamp: u64,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuctionCompleted {
    pub auction_id: u32,
    pub winner: Option<Address>,
    pub final_price: Option<i128>,
    pub timestamp: u64,
}
