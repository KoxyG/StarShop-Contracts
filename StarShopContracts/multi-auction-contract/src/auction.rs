use crate::event::{AuctionCanceled, AuctionCompleted, AuctionCreated, NewBidPlaced};
use crate::traits::AuctionTrait;
use crate::{bid::record_bid, errors::AuctionError};
use crate::{distribution, types::*};
use soroban_sdk::{
    contract, contractimpl, contracttype, panic_with_error, Address, Env, IntoVal, Symbol, Val,
};

#[contract]
pub struct AuctionContract;

/// Enum representing keys used to store contract data in Soroban storage.
#[contracttype]
#[derive(Clone)]
enum DataKey {
    TotalAuctions,        // Key for storing total number of auctions
    Auction(u32),         // Key for storing a specific Auction by its internal ID
    HasBid(Address, u32), // Key for storing if a user has made a bid for a specific auction
}

#[contractimpl]
impl AuctionTrait for AuctionContract {
    /// Creates a new auction with provided metadata and auction conditions.
    fn create_auction(
        env: Env,
        owner: Address,
        token: Address,
        item_metadata: ItemMetadata,
        auction_conditions: AuctionConditions,
    ) {
        owner.require_auth(); // Ensure caller is authenticated as the auction creator

        // Validate the item metadata (e.g., name, description, etc.)
        item_metadata.validate_item_data(&env);

        // Validate custom auction conditions (e.g., end time, floor price)
        auction_conditions.validate_conditions(&env);

        // Fetch the current number of auctions
        let total_auctions = Self::_get_total_auctions(&env);
        let auction_id = total_auctions + 1;

        let current_time = env.ledger().timestamp();

        // Initialize the auction with default state
        let auction = Auction {
            id: auction_id,
            owner: owner.clone(),
            item_metadata,
            auction_conditions: auction_conditions.clone(),
            start_time: current_time,
            curr_bid_amount: Option::None,
            curr_bidder: Option::None,
            no_of_bids: 0,
            no_of_participants: 0,
            last_bid_time: 0,
            token,
            auction_status: AuctionStatus::Active,
        };

        // Persist auction data to storage
        Self::_save_auction(&env, auction_id, &auction);

        // Update total auctions count
        Self::_save_total_auctions(&env, &total_auctions);

        // Emit Auction Created event
        env.events().publish(
            (Symbol::new(&env, "new_auction_created"), owner.clone()),
            AuctionCreated {
                auction_id,
                owner,
                start_time: auction.start_time,
                end_time: auction_conditions.end_time,
            },
        );
    }

    /// Places a bid on an active auction.
    fn make_bid(env: Env, auction_id: u32, bidder: Address, bid_amount: i128) {
        bidder.require_auth(); // Ensure bidder is authenticated

        let auction_data = Self::_get_auction(&env, auction_id);

        if auction_data.is_none() {
            panic_with_error!(&env, AuctionError::AuctionNotFound); // Auction must exist
        }

        let mut auction_data = auction_data.unwrap();

        // Reject if the auction was canceled or already completed
        if auction_data.is_canceled() {
            panic_with_error!(&env, AuctionError::AuctionCanceled);
        }

        if auction_data.is_completed() {
            panic_with_error!(&env, AuctionError::AuctionCompleted);
        }

        // Perform the bid and update state
        record_bid(&env, &mut auction_data, bidder.clone(), bid_amount);

        // Check if bidder is a new participant
        if !Self::_has_bid(&env, &bidder, &auction_id) {
            Self::_register_user_bid(&env, &bidder, &auction_id);
            auction_data.no_of_participants += 1;
        }

        // Save updated auction state
        Self::_save_auction(&env, auction_id, &auction_data);

        // Emit New Bid event
        env.events().publish(
            (Symbol::new(&env, "new_bid_placed"), bidder.clone()),
            NewBidPlaced {
                auction_id,
                bidder,
                bid_amount,
            },
        );
    }

    /// Cancels an active auction if it's still cancelable.
    fn cancel_auction(env: Env, auction_id: u32) {
        let auction_data = Self::_get_auction(&env, auction_id);

        if auction_data.is_none() {
            panic_with_error!(&env, AuctionError::AuctionNotFound);
        }

        let mut auction_data = auction_data.unwrap();

        auction_data.owner.require_auth(); // Only owner can cancel

        // Prevent double-cancel or cancellation after completion
        if auction_data.is_canceled() {
            panic_with_error!(&env, AuctionError::AuctionCanceled);
        }

        if auction_data.is_completed() {
            panic_with_error!(&env, AuctionError::AuctionCompleted);
        }

        // Check if auction meets the cancel conditions
        if !auction_data.can_cancel() {
            panic_with_error!(&env, AuctionError::CannotCancelAuction);
        }

        // Mark the auction as canceled and save
        auction_data.auction_status = AuctionStatus::Cancelled;

        Self::_save_auction(&env, auction_id, &auction_data);

        // Emit Auction Canceled event
        env.events().publish(
            (
                Symbol::new(&env, "auction_canceled"),
                auction_data.owner.clone(),
            ),
            AuctionCanceled {
                auction_id,
                owner: auction_data.owner,
                timestamp: env.ledger().timestamp(),
            },
        );
    }

    /// Ends an auction if its end conditions are met.
    fn end_auction(env: Env, auction_id: u32) {
        let auction_data = Self::_get_auction(&env, auction_id);

        if auction_data.is_none() {
            panic_with_error!(&env, AuctionError::AuctionNotFound);
        }

        let mut auction_data = auction_data.unwrap();

        auction_data.owner.require_auth(); // Only owner can end the auction

        // Prevent double-ending or ending a canceled auction
        if auction_data.is_canceled() {
            panic_with_error!(&env, AuctionError::AuctionCanceled);
        }

        if auction_data.is_completed() {
            panic_with_error!(&env, AuctionError::AuctionCompleted);
        }

        // Check if any of the custom end conditions are met
        auction_data.check_can_end(&env);

        // If there is a current bidder, transfer the item and update owner
        if let Some(curr_bidder) = &auction_data.curr_bidder {
            let bid_amount = auction_data.curr_bid_amount.expect("Missing bid amount");

            let prev_owner = auction_data.owner;
            auction_data.owner = curr_bidder.clone();

            // Transfer bid amount from contract to seller
            distribution::transfer_from_contract(
                &env,
                &auction_data.token,
                &prev_owner,
                &bid_amount,
            );
        }

        // Update auction status to completed
        auction_data.auction_status = AuctionStatus::Completed;

        // Save updated auction state
        Self::_save_auction(&env, auction_id, &auction_data);

        env.events().publish(
            (
                Symbol::new(&env, "auction_completed"),
                auction_data.curr_bidder.clone(),
            ),
            AuctionCompleted {
                auction_id,
                winner: auction_data.curr_bidder,
                final_price: auction_data.curr_bid_amount,
                timestamp: env.ledger().timestamp(),
            },
        );
    }

    fn get_auction(env: Env, auction_id: u32) -> Option<Auction> {
        Self::_get_auction(&env, auction_id)
    }
}

impl AuctionContract {
    /// Internal helper to fetch a auction from storage.
    fn _get_auction(env: &Env, auction_id: u32) -> Option<Auction> {
        env.storage()
            .instance()
            .get::<Val, Auction>(&DataKey::Auction(auction_id).into_val(env))
    }

    /// Internal helper to save a auction to storage.
    fn _save_auction(env: &Env, auction_id: u32, auction: &Auction) {
        env.storage()
            .instance()
            .set::<Val, Auction>(&DataKey::Auction(auction_id).into_val(env), auction);
    }

    /// Internal helper to get total number of auctions
    fn _get_total_auctions(env: &Env) -> u32 {
        env.storage()
            .instance()
            .get::<Val, u32>(&DataKey::TotalAuctions.into_val(env))
            .unwrap_or(0) // Default to 0 if no auction exist
    }

    /// Internal helper to save total number of auctions to storage.
    fn _save_total_auctions(env: &Env, total_auctions: &u32) {
        env.storage()
            .instance()
            .set::<Val, u32>(&DataKey::TotalAuctions.into_val(env), total_auctions);
    }

    /// Internal helper to check if auction_id exists
    fn _check_auction_id(env: &Env, auction_id: u32) -> bool {
        env.storage()
            .instance()
            .has::<Val>(&DataKey::Auction(auction_id).into_val(env))
    }

    /// Internal helper to register that a user has bid for an auction.
    fn _register_user_bid(env: &Env, bidder: &Address, auction_id: &u32) {
        env.storage().instance().set::<Val, bool>(
            &DataKey::HasBid(bidder.clone(), auction_id.clone()).into_val(env),
            &true,
        );
    }

    /// Internal helper to check if a user has bid for an auction
    fn _has_bid(env: &Env, bidder: &Address, auction_id: &u32) -> bool {
        env.storage()
            .instance()
            .has::<Val>(&DataKey::HasBid(bidder.clone(), auction_id.clone()).into_val(env))
    }
}
