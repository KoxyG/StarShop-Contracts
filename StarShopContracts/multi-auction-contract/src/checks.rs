use soroban_sdk::{panic_with_error, Env};

use crate::{
    errors::{ConditionError, ValidationError},
    types::*,
};

impl ItemMetadata {
    pub fn validate_item_data(&self, env: &Env) {
        // Ensure the auction title is not empty
        if self.title.is_empty() {
            panic_with_error!(&env, ValidationError::AuctionNameCannotBeEmpty)
        }

        // Ensure the auction description is not empty
        if self.title.is_empty() {
            panic_with_error!(&env, ValidationError::AuctionDescriptionCannotBeEmpty)
        }
    }
}

impl Auction {
    pub fn is_canceled(&self) -> bool {
        // Check if the auction status is "Cancelled"
        self.auction_status == AuctionStatus::Cancelled
    }

    pub fn is_completed(&self) -> bool {
        // Check if the auction status is "Completed"
        self.auction_status == AuctionStatus::Completed
    }

    pub fn can_cancel(&self) -> bool {
        // Allow cancellation only if the auction is active and has no bids
        match self.auction_status {
            AuctionStatus::Active => self.no_of_bids == 0,
            _ => false,
        }
    }

    pub fn check_can_bid(&self, env: &Env, bid_amount: &i128) {
        let conditions = &self.auction_conditions;

        // Check if the auction has ended based on the current time
        let current_time = env.ledger().timestamp();
        if current_time > conditions.end_time {
            panic_with_error!(&env, ConditionError::AuctionEnded)
        }

        // Check if the maximum bid count has been reached
        if let Some(bid_count) = conditions.on_bid_count {
            if self.no_of_bids + 1 > bid_count {
                panic_with_error!(&env, ConditionError::MaxBidCountReached);
            }
        }

        // Check if the target price has been reached
        if let Some(target_price) = conditions.on_target_price {
            if let Some(curr_bid_amount) = self.curr_bid_amount {
                match conditions.auction_type {
                    AuctionType::Regular => {
                        if curr_bid_amount >= target_price {
                            panic_with_error!(&env, ConditionError::TargetPriceReached);
                        }
                    }
                    AuctionType::Reverse => {
                        if curr_bid_amount <= target_price {
                            panic_with_error!(&env, ConditionError::TargetPriceReached);
                        }
                    }
                    _ => (),
                }
            }
        }

        // Check if the maximum inactivity time has been exceeded
        if let Some(inactivity_seconds) = conditions.on_inactivity_seconds {
            let time_elasped = current_time - self.last_bid_time;

            if time_elasped >= inactivity_seconds {
                panic_with_error!(&env, ConditionError::MaxInactivitySecondsExceeded);
            }
        }

        // Check if the current sequence number exceeds the target sequence number
        if let Some(target_sequence_number) = conditions.on_fixed_sequence_number {
            let curr_sequence_number = env.ledger().sequence();

            if curr_sequence_number >= target_sequence_number {
                panic_with_error!(&env, ConditionError::TargetSequenceNumberReached);
            }
        }

        // Check if the maximum number of participants has been reached
        if let Some(max_participants) = conditions.on_maximum_participants {
            if self.no_of_participants + 1 >= max_participants {
                panic_with_error!(&env, ConditionError::MaxNumParticipantsReached);
            }
        }

        let bid_amount = bid_amount.clone();

        // Match auction type and validate bid logic
        let starting_price = conditions.starting_price;
        match &conditions.auction_type {
            AuctionType::Regular => {
                // Regular auction: bid must be higher than the current bid or starting price
                match self.curr_bid_amount {
                    Option::Some(curr_bid_amount) => {
                        if curr_bid_amount >= bid_amount {
                            panic_with_error!(&env, ConditionError::BidMustBeHigherThanMaxBid)
                        }
                    }
                    Option::None => {
                        if starting_price >= bid_amount {
                            panic_with_error!(
                                &env,
                                ConditionError::BidMustBeHigherThanStartingPrice
                            )
                        }
                    }
                }
            }
            AuctionType::Reverse => {
                // Reverse auction: bid must be lower than the current bid or starting price
                match self.curr_bid_amount {
                    Option::Some(curr_bid_amount) => {
                        if bid_amount >= curr_bid_amount {
                            panic_with_error!(&env, ConditionError::BidMustBeLowerThanMaxBid)
                        }
                    }
                    Option::None => {
                        if bid_amount >= starting_price {
                            panic_with_error!(&env, ConditionError::BidMustBeLowerThanStartingPrice)
                        }
                    }
                }
            }
            AuctionType::Dutch(duction_auction) => {
                // Dutch auction: only one bid is allowed, and it must be higher than the current price
                if self.curr_bid_amount.is_some() {
                    panic_with_error!(&env, ConditionError::DutchBidAlreadyRegistered)
                }

                let current_price = duction_auction.calculate_current_price(
                    env,
                    conditions.starting_price,
                    self.start_time,
                    conditions.end_time,
                );

                if bid_amount != current_price {
                    panic_with_error!(&env, ConditionError::BidMustMatchDutchPrice)
                }
            }
        }
    }

    pub fn check_can_end(&self, env: &Env) {
        let conditions = &self.auction_conditions;
        let current_time = env.ledger().timestamp();

        if current_time >= conditions.end_time {
            return;
        }

        // Check if the required bid count has been reached
        if let Some(bid_count) = conditions.on_bid_count {
            if bid_count > self.no_of_bids {
                panic_with_error!(&env, ConditionError::MaxBidCountNotReached);
            } else {
                return;
            }
        }

        // Check if the target price has been reached
        if let Some(target_price) = conditions.on_target_price {
            if let Some(curr_bid_amount) = self.curr_bid_amount {
                if curr_bid_amount < target_price {
                    panic_with_error!(&env, ConditionError::TargetPriceNotReached);
                } else {
                    return;
                }
            }
        }

        // Check if the required inactivity time has been reached
        if let Some(inactivity_seconds) = conditions.on_inactivity_seconds {
            let time_elasped = current_time - self.last_bid_time;

            if time_elasped < inactivity_seconds {
                panic_with_error!(&env, ConditionError::MaxInactivitySecondsNotReached);
            } else {
                return;
            }
        }

        // Check if the required sequence number has been reached
        if let Some(target_sequence_number) = conditions.on_fixed_sequence_number {
            let curr_sequence_number = env.ledger().sequence();

            if curr_sequence_number < target_sequence_number {
                panic_with_error!(&env, ConditionError::TargetSequenceNumberNotReached);
            } else {
                return;
            }
        }

        // Check if the minimum number of participants has been reached
        if let Some(min_participants) = conditions.on_minimum_participants {
            if self.no_of_participants < min_participants {
                panic_with_error!(&env, ConditionError::MinNumParticipantsNotReached);
            } else {
                return;
            }
        }

        // Check if the maximum number of participants has been reached
        if let Some(max_participants) = conditions.on_maximum_participants {
            if self.no_of_participants < max_participants {
                panic_with_error!(&env, ConditionError::MaxNumParticipantsNotReached);
            } else {
                return;
            }
        }

        // For Dutch auctions, ensure at least one bid has been registered
        if let AuctionType::Dutch(_) = conditions.auction_type {
            if self.curr_bid_amount.is_none() {
                panic_with_error!(&env, ConditionError::NoBidsRegisteredYet)
            } else {
                return;
            }
        }

        // If none of the above conditions are met, the auction has not ended
        panic_with_error!(&env, ConditionError::AuctionNotEnded);
    }
}

impl DutchAuctionData {
    pub fn calculate_current_price(
        &self,
        env: &Env,
        start_price: i128,
        start_time: u64,
        end_time: u64,
    ) -> i128 {
        let current_time = env.ledger().timestamp();

        // If the current time is past the end time, return the floor price
        if current_time >= end_time {
            return self.floor_price;
        }

        // Calculate the price decrease based on elapsed time
        let duration = end_time - start_time;
        let elapsed = current_time - start_time;
        let price_diff = start_price - self.floor_price;

        let price_decrease = (price_diff as i128 * elapsed as i128) / duration as i128;

        // Return the current price
        start_price - price_decrease
    }
}

impl AuctionConditions {
    pub fn validate_conditions(&self, env: &Env) {
        let current_time = env.ledger().timestamp();

        // Ensure the auction end time is in the future
        if self.end_time < current_time {
            panic_with_error!(&env, ValidationError::EndTimeInPast)
        }

        // Ensure the starting price is greater than zero
        if self.starting_price == 0 {
            panic_with_error!(&env, ValidationError::StartingPriceCannotBeZero);
        }

        // Validate optional conditions
        if let Some(on_bid_count) = self.on_bid_count {
            if on_bid_count == 0 {
                panic_with_error!(&env, ValidationError::BidCountMustBeGreaterThanZero);
            }
        }

        if let Some(on_target_price) = self.on_target_price {
            if on_target_price == 0 {
                panic_with_error!(&env, ValidationError::TargetPriceMustBeGreaterThanZero);
            }
        }

        if let Some(on_inactivity_seconds) = self.on_inactivity_seconds {
            if on_inactivity_seconds == 0 {
                panic_with_error!(
                    &env,
                    ValidationError::InactivitySecondsMustBeGreaterThanZero
                );
            }
        }

        if let Some(on_fixed_sequence_number) = self.on_fixed_sequence_number {
            if on_fixed_sequence_number == 0 {
                panic_with_error!(&env, ValidationError::SequenceNumberMustBeGreaterThanZero);
            }
        }

        if let Some(on_minimum_participants) = self.on_minimum_participants {
            if on_minimum_participants == 0 {
                panic_with_error!(
                    &env,
                    ValidationError::MinimumParticipantsMustBeGreaterThanZero
                );
            }
        }

        if let Some(on_maximum_participants) = self.on_maximum_participants {
            if on_maximum_participants == 0 {
                panic_with_error!(
                    &env,
                    ValidationError::MaximumParticipantsMustBeGreaterThanZero
                );
            }
        }

        // Validate Dutch auction-specific conditions
        if let AuctionType::Dutch(dutch_auction) = &self.auction_type {
            if dutch_auction.floor_price == 0 {
                panic_with_error!(
                    &env,
                    ValidationError::DutchAuctionFloorPriceMustBeGreaterThanZero
                );
            }
        }
    }

    // Only useful for exposing ducth auction current price
    pub fn get_item_current_price(&self, env: &Env, start_time: u64) -> i128 {
        if let AuctionType::Dutch(dutch_data) = &self.auction_type {
            dutch_data.calculate_current_price(&env, self.starting_price, start_time, self.end_time)
        } else {
            0
        }
    }
}
