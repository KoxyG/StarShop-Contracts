use soroban_sdk::{Address, Env};

use crate::{distribution, types::*};

pub fn record_bid(
    env: &Env,
    auction_data: &mut Auction,
    new_bidder: Address,
    new_bid_amount: i128,
) {
    // Check if user can bid
    auction_data.check_can_bid(env, &new_bid_amount);

    // Transfer tokens to contract
    distribution::transfer_to_contract(&env, &auction_data.token, &new_bidder, &new_bid_amount);

    // Check if prev bidder and refund
    if let Some(prev_bidder) = &auction_data.curr_bidder {
        let prev_bid_amount = auction_data
            .curr_bid_amount
            .expect("Missing previous bid amount");

        distribution::transfer_from_contract(
            &env,
            &auction_data.token,
            &prev_bidder,
            &prev_bid_amount,
        );
    }

    // Update curr_bids and increment bid_count
    auction_data.curr_bidder = Option::Some(new_bidder.clone());
    auction_data.curr_bid_amount = Option::Some(new_bid_amount.clone());
    auction_data.no_of_bids += 1;
}
