use crate::types::*;
use soroban_sdk::{Address, Env};

/// Interface for the Auction contract.
pub trait AuctionTrait {
    /// Create a new auction in the auction marketplace.
    fn create_auction(
        env: Env,
        owner: Address,
        token: Address,
        item_metadata: ItemMetadata,
        auction_conditions: AuctionConditions,
    );

    fn make_bid(env: Env, auction_id: u32, bidder: Address, bid_amount: i128);

    fn cancel_auction(env: Env, auction_id: u32);

    fn end_auction(env: Env, auction_id: u32);

    fn get_auction(env: Env, auction_id: u32) -> Option<Auction>;
}
