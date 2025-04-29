use crate::types::*;

pub struct AuctionConditionsBuilder {
    auction_type: AuctionType,
    end_time: u64,
    starting_price: i128,
    on_bid_count: Option<u32>,
    on_target_price: Option<i128>,
    on_inactivity_seconds: Option<u64>,
    on_fixed_sequence_number: Option<u32>,
    on_minimum_participants: Option<u32>,
    on_maximum_participants: Option<u32>,
}

impl AuctionConditionsBuilder {
    /// Initialize the builder with required fields.
    pub fn new(auction_type: AuctionType, end_time: u64, starting_price: i128) -> Self {
        Self {
            auction_type,
            end_time,
            starting_price,
            on_bid_count: None,
            on_target_price: None,
            on_inactivity_seconds: None,
            on_fixed_sequence_number: None,
            on_minimum_participants: None,
            on_maximum_participants: None,
        }
    }

    // Set optional fields

    pub fn on_bid_count(mut self, count: u32) -> Self {
        self.on_bid_count = Some(count);
        self
    }

    pub fn on_target_price(mut self, price: i128) -> Self {
        self.on_target_price = Some(price);
        self
    }

    pub fn on_inactivity_seconds(mut self, seconds: u64) -> Self {
        self.on_inactivity_seconds = Some(seconds);
        self
    }

    pub fn on_fixed_sequence_number(mut self, seq: u32) -> Self {
        self.on_fixed_sequence_number = Some(seq);
        self
    }

    pub fn on_minimum_participants(mut self, min: u32) -> Self {
        self.on_minimum_participants = Some(min);
        self
    }

    pub fn on_maximum_participants(mut self, max: u32) -> Self {
        self.on_maximum_participants = Some(max);
        self
    }

    /// Finally, build the AuctionConditions.
    pub fn build(self) -> AuctionConditions {
        AuctionConditions {
            auction_type: self.auction_type,
            end_time: self.end_time,
            starting_price: self.starting_price,
            on_bid_count: self.on_bid_count,
            on_target_price: self.on_target_price,
            on_inactivity_seconds: self.on_inactivity_seconds,
            on_fixed_sequence_number: self.on_fixed_sequence_number,
            on_minimum_participants: self.on_minimum_participants,
            on_maximum_participants: self.on_maximum_participants,
        }
    }
}
