#![cfg(test)]

// use super::*;
use crate::auction::{AuctionContract, AuctionContractClient};
use crate::types::{AuctionStatus, AuctionType, DutchAuctionData, ItemMetadata};
use soroban_sdk::testutils::{Address as _, Ledger};
use soroban_sdk::token::{StellarAssetClient, TokenClient};
use soroban_sdk::{token, Address, Env, String};

use crate::utils::AuctionConditionsBuilder;

struct Auction {
    env: Env,
    owner: Address,
    item_metadata: ItemMetadata,
    client: AuctionContractClient<'static>,
    token: TokenClient<'static>,
    token_admin: StellarAssetClient<'static>,
}

fn create_token_contract<'a>(
    e: &Env,
    admin: &Address,
) -> (token::Client<'a>, token::StellarAssetClient<'a>) {
    let sac = e.register_stellar_asset_contract_v2(admin.clone());
    (
        token::Client::new(e, &sac.address()),
        token::StellarAssetClient::new(e, &sac.address()),
    )
}

impl Auction {
    fn new() -> Self {
        let env = Env::default();
        env.cost_estimate().budget().reset_unlimited();

        env.mock_all_auths();

        let auction_address = env.register(AuctionContract, ());
        let client = AuctionContractClient::new(&env, &auction_address);
        let owner = Address::generate(&env);

        let item_metadata = ItemMetadata {
            title: String::from_str(&env, "Auction Item"),
            description: String::from_str(&env, "Item description"),
        };

        let (token, token_admin) = create_token_contract(&env, &owner);

        Auction {
            env,
            client,
            owner,
            item_metadata,
            token,
            token_admin,
        }
    }
}

#[test]
fn test_auction_creation() {
    let Auction {
        client,
        item_metadata,
        token,
        owner,
        ..
    } = Auction::new();

    let auction_conditions = AuctionConditionsBuilder::new(AuctionType::Regular, 1000, 100).build();

    client.create_auction(&owner, &token.address, &item_metadata, &auction_conditions);

    let auction_id = 1;

    let auction = client.get_auction(&auction_id);

    assert!(auction.is_some(), "auction should exist");

    let auction = auction.unwrap();
    assert!(
        auction.auction_conditions.auction_type == AuctionType::Regular,
        "Auction type should match"
    );
    assert!(
        auction.auction_conditions.starting_price == 100,
        "Starting price should match"
    );
    assert!(
        auction.auction_conditions.end_time == 1000,
        "End time should match"
    );
    assert!(
        auction.item_metadata.title == item_metadata.title,
        "Item title should match"
    );
    assert!(
        auction.item_metadata.description == item_metadata.description,
        "Item description should match"
    );
    assert!(auction.owner == owner, "Auction owner should match");
    assert!(auction.token == token.address, "Token address should match");
    assert!(
        auction.auction_status == AuctionStatus::Active,
        "Auction status should match"
    )
}

#[test]
#[should_panic(expected = "#111")]
fn test_auction_creation_failed_invalid_end_date() {
    let Auction {
        client,
        item_metadata,
        token,
        owner,
        env,
        ..
    } = Auction::new();

    let auction_conditions = AuctionConditionsBuilder::new(AuctionType::Regular, 1000, 100).build();

    // set ledger ahead of end date
    env.ledger().set_timestamp(5000);

    client.create_auction(&owner, &token.address, &item_metadata, &auction_conditions);
}

#[test]
#[should_panic(expected = "#104")]
fn test_auction_creation_failed_invalid_starting_price() {
    let Auction {
        client,
        item_metadata,
        token,
        owner,
        ..
    } = Auction::new();

    let auction_conditions = AuctionConditionsBuilder::new(AuctionType::Regular, 1000, 0).build();

    client.create_auction(&owner, &token.address, &item_metadata, &auction_conditions);
}

#[test]
#[should_panic(expected = "#105")]
fn test_auction_creation_failed_invalid_bid_count() {
    let Auction {
        client,
        item_metadata,
        token,
        owner,
        ..
    } = Auction::new();

    let auction_conditions = AuctionConditionsBuilder::new(AuctionType::Regular, 1000, 100)
        .on_bid_count(0)
        .build();

    client.create_auction(&owner, &token.address, &item_metadata, &auction_conditions);
}

#[test]
#[should_panic(expected = "#106")]
fn test_auction_creation_failed_invalid_target_price() {
    let Auction {
        client,
        item_metadata,
        token,
        owner,
        ..
    } = Auction::new();

    let auction_conditions = AuctionConditionsBuilder::new(AuctionType::Regular, 1000, 100)
        .on_target_price(0)
        .build();

    client.create_auction(&owner, &token.address, &item_metadata, &auction_conditions);
}

#[test]
#[should_panic(expected = "#107")]
fn test_auction_creation_failed_invalid_inactivity_seconds() {
    let Auction {
        client,
        item_metadata,
        token,
        owner,
        ..
    } = Auction::new();

    let auction_conditions = AuctionConditionsBuilder::new(AuctionType::Regular, 1000, 100)
        .on_inactivity_seconds(0)
        .build();

    client.create_auction(&owner, &token.address, &item_metadata, &auction_conditions);
}

#[test]
#[should_panic(expected = "#108")]
fn test_auction_creation_failed_invalid_sequence_number() {
    let Auction {
        client,
        item_metadata,
        token,
        owner,
        ..
    } = Auction::new();

    let auction_conditions = AuctionConditionsBuilder::new(AuctionType::Regular, 1000, 100)
        .on_fixed_sequence_number(0)
        .build();

    client.create_auction(&owner, &token.address, &item_metadata, &auction_conditions);
}

#[test]
#[should_panic(expected = "#109")]
fn test_auction_creation_failed_invalid_min_participants() {
    let Auction {
        client,
        item_metadata,
        token,
        owner,
        ..
    } = Auction::new();

    let auction_conditions = AuctionConditionsBuilder::new(AuctionType::Regular, 1000, 100)
        .on_minimum_participants(0)
        .build();

    client.create_auction(&owner, &token.address, &item_metadata, &auction_conditions);
}

#[test]
#[should_panic(expected = "#113")]
fn test_auction_creation_failed_invalid_max_participants() {
    let Auction {
        client,
        item_metadata,
        token,
        owner,
        ..
    } = Auction::new();

    let auction_conditions = AuctionConditionsBuilder::new(AuctionType::Regular, 1000, 100)
        .on_maximum_participants(0)
        .build();

    client.create_auction(&owner, &token.address, &item_metadata, &auction_conditions);
}

#[test]
#[should_panic(expected = "#112")]
fn test_auction_creation_failed_invalid_floor_value() {
    let Auction {
        client,
        item_metadata,
        token,
        owner,
        ..
    } = Auction::new();

    let dutch_data = DutchAuctionData { floor_price: 0 };
    let auction_conditions =
        AuctionConditionsBuilder::new(AuctionType::Dutch(dutch_data), 1000, 100).build();

    client.create_auction(&owner, &token.address, &item_metadata, &auction_conditions);
}

#[test]
fn test_bid_regular_auction() {
    let Auction {
        client,
        item_metadata,
        token,
        owner,
        token_admin,
        env,
        ..
    } = Auction::new();

    let auction_conditions = AuctionConditionsBuilder::new(AuctionType::Regular, 1000, 100).build();

    client.create_auction(&owner, &token.address, &item_metadata, &auction_conditions);

    let auction_id = 1;

    let bidder = Address::generate(&env);
    let bid_amount = 1000;

    token_admin.mint(&bidder, &bid_amount);
    assert_eq!(token.balance(&bidder), 1000);

    client.make_bid(&auction_id, &bidder, &bid_amount);

    let auction = client.get_auction(&auction_id);

    assert!(auction.is_some(), "auction should exist");

    let auction = auction.unwrap();

    assert!(auction.curr_bidder.is_some(), "Auction bidder should exist");
    assert!(
        auction.curr_bid_amount.is_some(),
        "Auction bid amount should exist"
    );
    assert!(
        auction.curr_bidder.unwrap() == bidder,
        "Auction bidder should match"
    );
    assert!(
        auction.curr_bid_amount.unwrap() == bid_amount,
        "Auction bid amount should match"
    );
}

#[test]
#[should_panic(expected = "#308")]
fn test_bid_fail_regular_auction_lower_than_starting_price() {
    let Auction {
        client,
        item_metadata,
        token,
        owner,
        token_admin,
        env,
        ..
    } = Auction::new();

    let auction_conditions = AuctionConditionsBuilder::new(AuctionType::Regular, 1000, 100).build();

    client.create_auction(&owner, &token.address, &item_metadata, &auction_conditions);

    let auction_id = 1;

    let bidder = Address::generate(&env);
    let bid_amount = 90;

    token_admin.mint(&bidder, &bid_amount);
    assert_eq!(token.balance(&bidder), bid_amount);

    client.make_bid(&auction_id, &bidder, &bid_amount);
}

#[test]
fn test_multiple_bid_regular_auction() {
    let Auction {
        client,
        item_metadata,
        token,
        owner,
        token_admin,
        env,
        ..
    } = Auction::new();

    let auction_conditions = AuctionConditionsBuilder::new(AuctionType::Regular, 1000, 100).build();

    client.create_auction(&owner, &token.address, &item_metadata, &auction_conditions);

    let auction_id = 1;

    // FIRST BID
    let bidder1 = Address::generate(&env);
    let bid_amount1 = 1000;

    token_admin.mint(&bidder1, &bid_amount1);
    assert_eq!(token.balance(&bidder1), bid_amount1);

    client.make_bid(&auction_id, &bidder1, &bid_amount1);

    // SECOND BID
    let bidder2 = Address::generate(&env);
    let bid_amount2 = 1500;

    token_admin.mint(&bidder2, &bid_amount2);
    assert_eq!(token.balance(&bidder2), bid_amount2);

    client.make_bid(&auction_id, &bidder2, &bid_amount2);

    // CHECK AUCTION
    let auction = client.get_auction(&auction_id);
    assert!(auction.is_some(), "auction should exist");

    let auction = auction.unwrap();

    assert!(auction.curr_bidder.is_some(), "Auction bidder should exist");
    assert!(
        auction.curr_bid_amount.is_some(),
        "Auction bid amount should exist"
    );
    assert!(
        auction.curr_bidder.unwrap() == bidder2,
        "Auction bidder should match"
    );
    assert!(
        auction.curr_bid_amount.unwrap() == bid_amount2,
        "Auction bid amount should match"
    );
}

#[test]
#[should_panic(expected = "#307")]
fn test_multiple_bid_fail_regular_auction_lower_than_curr_max_bid() {
    let Auction {
        client,
        item_metadata,
        token,
        owner,
        token_admin,
        env,
        ..
    } = Auction::new();

    let auction_conditions = AuctionConditionsBuilder::new(AuctionType::Regular, 1000, 100).build();

    client.create_auction(&owner, &token.address, &item_metadata, &auction_conditions);

    let auction_id = 1;

    // FIRST BID
    let bidder1 = Address::generate(&env);
    let bid_amount1 = 1000;

    token_admin.mint(&bidder1, &bid_amount1);
    assert_eq!(token.balance(&bidder1), bid_amount1);

    client.make_bid(&auction_id, &bidder1, &bid_amount1);

    // SECOND BID
    let bidder2 = Address::generate(&env);
    let bid_amount2 = 700;

    token_admin.mint(&bidder2, &bid_amount2);
    assert_eq!(token.balance(&bidder2), bid_amount2);

    client.make_bid(&auction_id, &bidder2, &bid_amount2);
}

#[test]
fn test_bid_reverse_auction() {
    let Auction {
        client,
        item_metadata,
        token,
        owner,
        token_admin,
        env,
        ..
    } = Auction::new();

    let auction_conditions = AuctionConditionsBuilder::new(AuctionType::Reverse, 1000, 100).build();

    client.create_auction(&owner, &token.address, &item_metadata, &auction_conditions);

    let auction_id = 1;

    let bidder = Address::generate(&env);
    let bid_amount = 50; // lower amount

    token_admin.mint(&bidder, &bid_amount);
    assert_eq!(token.balance(&bidder), bid_amount);

    client.make_bid(&auction_id, &bidder, &bid_amount);

    let auction = client.get_auction(&auction_id);

    assert!(auction.is_some(), "auction should exist");

    let auction = auction.unwrap();

    assert!(auction.curr_bidder.is_some(), "Auction bidder should exist");
    assert!(
        auction.curr_bid_amount.is_some(),
        "Auction bid amount should exist"
    );
    assert!(
        auction.curr_bidder.unwrap() == bidder,
        "Auction bidder should match"
    );
    assert!(
        auction.curr_bid_amount.unwrap() == bid_amount,
        "Auction bid amount should match"
    );
}

#[test]
#[should_panic(expected = "#310")]
fn test_bid_fail_reverse_auction_higher_than_starting_bid() {
    let Auction {
        client,
        item_metadata,
        token,
        owner,
        token_admin,
        env,
        ..
    } = Auction::new();

    let auction_conditions = AuctionConditionsBuilder::new(AuctionType::Reverse, 1000, 100).build();

    client.create_auction(&owner, &token.address, &item_metadata, &auction_conditions);

    let auction_id = 1;

    let bidder = Address::generate(&env);
    let bid_amount = 200; // lower amount

    token_admin.mint(&bidder, &bid_amount);
    assert_eq!(token.balance(&bidder), bid_amount);

    client.make_bid(&auction_id, &bidder, &bid_amount);
}

#[test]
fn test_multiple_bid_reverse_auction() {
    let Auction {
        client,
        item_metadata,
        token,
        owner,
        token_admin,
        env,
        ..
    } = Auction::new();

    let auction_conditions =
        AuctionConditionsBuilder::new(AuctionType::Reverse, 1000, 1000).build();

    client.create_auction(&owner, &token.address, &item_metadata, &auction_conditions);

    let auction_id = 1;

    // FIRST BID
    let bidder1 = Address::generate(&env);
    let bid_amount1 = 900; // lower amount

    token_admin.mint(&bidder1, &bid_amount1);
    assert_eq!(token.balance(&bidder1), bid_amount1);

    client.make_bid(&auction_id, &bidder1, &bid_amount1);

    // SECOND BID
    let bidder2 = Address::generate(&env);
    let bid_amount2 = 700; // lower amount

    token_admin.mint(&bidder2, &bid_amount2);
    assert_eq!(token.balance(&bidder2), bid_amount2);

    client.make_bid(&auction_id, &bidder2, &bid_amount2);

    // CHECK AUCTION
    let auction = client.get_auction(&auction_id);

    assert!(auction.is_some(), "auction should exist");

    let auction = auction.unwrap();

    assert!(auction.curr_bidder.is_some(), "Auction bidder should exist");
    assert!(
        auction.curr_bid_amount.is_some(),
        "Auction bid amount should exist"
    );
    assert!(
        auction.curr_bidder.unwrap() == bidder2,
        "Auction bidder should match"
    );
    assert!(
        auction.curr_bid_amount.unwrap() == bid_amount2,
        "Auction bid amount should match"
    );
}

#[test]
#[should_panic(expected = "#309")]
fn test_multiple_bid_fail_reverse_auction_higher_than_curr_lowest_bid() {
    let Auction {
        client,
        item_metadata,
        token,
        owner,
        token_admin,
        env,
        ..
    } = Auction::new();

    let auction_conditions =
        AuctionConditionsBuilder::new(AuctionType::Reverse, 1000, 1000).build();

    client.create_auction(&owner, &token.address, &item_metadata, &auction_conditions);

    let auction_id = 1;

    // FIRST BID
    let bidder1 = Address::generate(&env);
    let bid_amount1 = 900; // lower amount

    token_admin.mint(&bidder1, &bid_amount1);
    assert_eq!(token.balance(&bidder1), bid_amount1);

    client.make_bid(&auction_id, &bidder1, &bid_amount1);

    // SECOND BID
    let bidder2 = Address::generate(&env);
    let bid_amount2 = 2000; // lower amount

    token_admin.mint(&bidder2, &bid_amount2);
    assert_eq!(token.balance(&bidder2), bid_amount2);

    client.make_bid(&auction_id, &bidder2, &bid_amount2);
}

#[test]
fn test_bid_dutch_auction() {
    let Auction {
        client,
        item_metadata,
        token,
        owner,
        token_admin,
        env,
        ..
    } = Auction::new();

    env.ledger().set_timestamp(0);

    let dutch_data = DutchAuctionData { floor_price: 500 };

    let auction_conditions =
        AuctionConditionsBuilder::new(AuctionType::Dutch(dutch_data), 1000, 1000).build();

    client.create_auction(&owner, &token.address, &item_metadata, &auction_conditions);

    let auction_id = 1;

    let bidder = Address::generate(&env);

    // move timestamp to half of end_time; (between start-price and floor-price)

    env.ledger().set_timestamp(500);

    let expected_dutch_price = auction_conditions.get_item_current_price(&env, 0);

    assert_eq!(expected_dutch_price, 750);

    let bid_amount = expected_dutch_price; // lower amount

    token_admin.mint(&bidder, &bid_amount);
    assert_eq!(token.balance(&bidder), bid_amount);

    client.make_bid(&auction_id, &bidder, &bid_amount);

    let auction = client.get_auction(&auction_id);

    assert!(auction.is_some(), "auction should exist");

    let auction = auction.unwrap();

    assert!(auction.curr_bidder.is_some(), "Auction bidder should exist");
    assert!(
        auction.curr_bid_amount.is_some(),
        "Auction bid amount should exist"
    );
    assert!(
        auction.curr_bidder.unwrap() == bidder,
        "Auction bidder should match"
    );
    assert!(
        auction.curr_bid_amount.unwrap() == bid_amount,
        "Auction bid amount should match"
    );
}

#[test]
#[should_panic(expected = "#312")]
fn test_bid_fail_dutch_auction_not_equal_to_dutch_bid() {
    let Auction {
        client,
        item_metadata,
        token,
        owner,
        token_admin,
        env,
        ..
    } = Auction::new();

    env.ledger().set_timestamp(0);

    let dutch_data = DutchAuctionData { floor_price: 500 };

    let auction_conditions =
        AuctionConditionsBuilder::new(AuctionType::Dutch(dutch_data), 1000, 1000).build();

    client.create_auction(&owner, &token.address, &item_metadata, &auction_conditions);

    let auction_id = 1;

    let bidder = Address::generate(&env);

    // move timestamp to half of end_time; (between start-price and floor-price)

    env.ledger().set_timestamp(500);

    let expected_dutch_price = auction_conditions.get_item_current_price(&env, 0);

    assert_eq!(expected_dutch_price, 750);

    let bid_amount = 1000; // higher amount

    token_admin.mint(&bidder, &bid_amount);
    assert_eq!(token.balance(&bidder), bid_amount);

    client.make_bid(&auction_id, &bidder, &bid_amount);
}

#[test]
#[should_panic(expected = "#311")]
fn test_multiple_bid_fail_dutch_auction() {
    let Auction {
        client,
        item_metadata,
        token,
        owner,
        token_admin,
        env,
        ..
    } = Auction::new();

    env.ledger().set_timestamp(0);

    let dutch_data = DutchAuctionData { floor_price: 500 };

    let auction_conditions =
        AuctionConditionsBuilder::new(AuctionType::Dutch(dutch_data), 1000, 1000).build();

    client.create_auction(&owner, &token.address, &item_metadata, &auction_conditions);

    let auction_id = 1;

    // move timestamp to half of end_time; (between start-price and floor-price)

    env.ledger().set_timestamp(500);

    let expected_dutch_price = auction_conditions.get_item_current_price(&env, 0);

    assert_eq!(expected_dutch_price, 750);

    // First Bid
    let bidder1 = Address::generate(&env);
    let bid_amount1 = expected_dutch_price; // lower amount

    token_admin.mint(&bidder1, &bid_amount1);
    assert_eq!(token.balance(&bidder1), bid_amount1);

    client.make_bid(&auction_id, &bidder1, &bid_amount1);

    // Increment Timestamp
    env.ledger().set_timestamp(700);

    // Second Bid
    let bidder2 = Address::generate(&env);
    let expected_dutch_price = auction_conditions.get_item_current_price(&env, 0);
    let bid_amount2 = expected_dutch_price; // lower amount

    token_admin.mint(&bidder2, &bid_amount2);
    assert_eq!(token.balance(&bidder2), bid_amount2);

    client.make_bid(&auction_id, &bidder2, &bid_amount2);
}

// OTHER CONDITIONALs will use regular for these tests

#[test]
#[should_panic(expected = "#302")]
fn test_multiple_bid_fail_regular_auction_target_reached() {
    let Auction {
        client,
        item_metadata,
        token,
        owner,
        token_admin,
        env,
        ..
    } = Auction::new();

    let auction_conditions = AuctionConditionsBuilder::new(AuctionType::Regular, 1000, 100)
        .on_target_price(500)
        .build();

    client.create_auction(&owner, &token.address, &item_metadata, &auction_conditions);

    let auction_id = 1;

    // FIRST BID
    let bidder1 = Address::generate(&env);
    let bid_amount1 = 500; // target price

    token_admin.mint(&bidder1, &bid_amount1);
    assert_eq!(token.balance(&bidder1), bid_amount1);

    client.make_bid(&auction_id, &bidder1, &bid_amount1);

    // SECOND BID
    let bidder2 = Address::generate(&env);
    let bid_amount2 = 1500;

    token_admin.mint(&bidder2, &bid_amount2);
    assert_eq!(token.balance(&bidder2), bid_amount2);

    client.make_bid(&auction_id, &bidder2, &bid_amount2);
}

#[test]
#[should_panic(expected = "#301")]
fn test_multiple_bid_fail_max_bid_count_reached() {
    let Auction {
        client,
        item_metadata,
        token,
        owner,
        token_admin,
        env,
        ..
    } = Auction::new();

    let auction_conditions = AuctionConditionsBuilder::new(AuctionType::Regular, 1000, 100)
        .on_bid_count(1)
        .build();

    client.create_auction(&owner, &token.address, &item_metadata, &auction_conditions);

    let auction_id = 1;

    // FIRST BID
    let bidder1 = Address::generate(&env);
    let bid_amount1 = 500; // target price

    token_admin.mint(&bidder1, &bid_amount1);
    assert_eq!(token.balance(&bidder1), bid_amount1);

    client.make_bid(&auction_id, &bidder1, &bid_amount1);

    // SECOND BID
    let bidder2 = Address::generate(&env);
    let bid_amount2 = 1500;

    token_admin.mint(&bidder2, &bid_amount2);
    assert_eq!(token.balance(&bidder2), bid_amount2);

    client.make_bid(&auction_id, &bidder2, &bid_amount2);
}

#[test]
#[should_panic(expected = "#304")]
fn test_multiple_bid_fail_max_inactivity_seconds_reached() {
    let Auction {
        client,
        item_metadata,
        token,
        owner,
        token_admin,
        env,
        ..
    } = Auction::new();

    let auction_conditions = AuctionConditionsBuilder::new(AuctionType::Regular, 1000, 100)
        .on_inactivity_seconds(10)
        .build();

    client.create_auction(&owner, &token.address, &item_metadata, &auction_conditions);

    let auction_id = 1;

    // FIRST BID
    let bidder1 = Address::generate(&env);
    let bid_amount1 = 500; // target price

    token_admin.mint(&bidder1, &bid_amount1);
    assert_eq!(token.balance(&bidder1), bid_amount1);

    client.make_bid(&auction_id, &bidder1, &bid_amount1);

    env.ledger().set_timestamp(50);

    // SECOND BID
    let bidder2 = Address::generate(&env);
    let bid_amount2 = 1500;

    token_admin.mint(&bidder2, &bid_amount2);
    assert_eq!(token.balance(&bidder2), bid_amount2);

    client.make_bid(&auction_id, &bidder2, &bid_amount2);
}

#[test]
#[should_panic(expected = "#305")]
fn test_multiple_bid_fail_target_sequence_number_reached() {
    let Auction {
        client,
        item_metadata,
        token,
        owner,
        token_admin,
        env,
        ..
    } = Auction::new();

    env.ledger().set_sequence_number(0);

    let auction_conditions = AuctionConditionsBuilder::new(AuctionType::Regular, 1000, 100)
        .on_fixed_sequence_number(10)
        .build();

    client.create_auction(&owner, &token.address, &item_metadata, &auction_conditions);

    let auction_id = 1;

    // FIRST BID
    let bidder1 = Address::generate(&env);
    let bid_amount1 = 500; // target price

    token_admin.mint(&bidder1, &bid_amount1);
    assert_eq!(token.balance(&bidder1), bid_amount1);

    client.make_bid(&auction_id, &bidder1, &bid_amount1);

    env.ledger().set_sequence_number(11);

    // SECOND BID
    let bidder2 = Address::generate(&env);
    let bid_amount2 = 1500;

    token_admin.mint(&bidder2, &bid_amount2);
    assert_eq!(token.balance(&bidder2), bid_amount2);

    client.make_bid(&auction_id, &bidder2, &bid_amount2);
}

#[test]
fn test_auction_cancelation() {
    let Auction {
        client,
        item_metadata,
        token,
        owner,
        ..
    } = Auction::new();

    let auction_conditions = AuctionConditionsBuilder::new(AuctionType::Regular, 1000, 100).build();

    client.create_auction(&owner, &token.address, &item_metadata, &auction_conditions);

    let auction_id = 1;

    client.cancel_auction(&auction_id);

    let auction = client.get_auction(&auction_id);

    assert!(auction.is_some(), "auction should exist");

    let auction = auction.unwrap();

    assert!(
        auction.auction_status == AuctionStatus::Cancelled,
        "Auction status should match"
    )
}

#[test]
#[should_panic(expected = "#204")]
fn test_auction_cancelation_fail_due_to_registered_bid() {
    let Auction {
        client,
        item_metadata,
        token,
        owner,
        token_admin,
        env,
        ..
    } = Auction::new();

    let auction_conditions = AuctionConditionsBuilder::new(AuctionType::Regular, 1000, 100).build();

    client.create_auction(&owner, &token.address, &item_metadata, &auction_conditions);

    let auction_id = 1;

    // FIRST BID
    let bidder1 = Address::generate(&env);
    let bid_amount1 = 1000;

    token_admin.mint(&bidder1, &bid_amount1);
    assert_eq!(token.balance(&bidder1), bid_amount1);

    client.make_bid(&auction_id, &bidder1, &bid_amount1);

    client.cancel_auction(&auction_id);
}

#[test]
fn test_end_regular_auction_with_bids() {
    let Auction {
        client,
        item_metadata,
        token,
        owner,
        token_admin,
        env,
        ..
    } = Auction::new();

    let auction_conditions = AuctionConditionsBuilder::new(AuctionType::Regular, 1000, 100).build();

    client.create_auction(&owner, &token.address, &item_metadata, &auction_conditions);

    let auction_id = 1;

    let bidder = Address::generate(&env);
    let bid_amount = 1000;

    token_admin.mint(&bidder, &bid_amount);
    assert_eq!(token.balance(&bidder), 1000);

    client.make_bid(&auction_id, &bidder, &bid_amount);

    // move to end
    env.ledger().set_timestamp(1200);

    client.end_auction(&auction_id);

    let auction = client.get_auction(&auction_id);

    assert!(auction.is_some(), "auction should exist");

    let auction = auction.unwrap();

    assert!(auction.owner == bidder, "Auction owner should exist");
    assert!(
        auction.auction_status == AuctionStatus::Completed,
        "Auction status should match"
    );
}

#[test]
fn test_end_regular_auction_when_target_reached() {
    let Auction {
        client,
        item_metadata,
        token,
        owner,
        token_admin,
        env,
        ..
    } = Auction::new();

    let auction_conditions = AuctionConditionsBuilder::new(AuctionType::Regular, 1000, 100)
        .on_target_price(500)
        .build();

    client.create_auction(&owner, &token.address, &item_metadata, &auction_conditions);

    let auction_id = 1;

    let bidder = Address::generate(&env);
    let bid_amount = 1000;

    token_admin.mint(&bidder, &bid_amount);
    assert_eq!(token.balance(&bidder), 1000);

    client.make_bid(&auction_id, &bidder, &bid_amount);

    client.end_auction(&auction_id);

    let auction = client.get_auction(&auction_id);

    assert!(auction.is_some(), "auction should exist");

    let auction = auction.unwrap();

    assert!(auction.owner == bidder, "Auction owner should exist");
    assert!(
        auction.auction_status == AuctionStatus::Completed,
        "Auction status should match"
    );
}

#[test]
fn test_end_regular_auction_when_bid_count_reached() {
    let Auction {
        client,
        item_metadata,
        token,
        owner,
        token_admin,
        env,
        ..
    } = Auction::new();

    let auction_conditions = AuctionConditionsBuilder::new(AuctionType::Regular, 1000, 100)
        .on_bid_count(1)
        .build();

    client.create_auction(&owner, &token.address, &item_metadata, &auction_conditions);

    let auction_id = 1;

    let bidder = Address::generate(&env);
    let bid_amount = 1000;

    token_admin.mint(&bidder, &bid_amount);
    assert_eq!(token.balance(&bidder), 1000);

    client.make_bid(&auction_id, &bidder, &bid_amount);

    client.end_auction(&auction_id);

    let auction = client.get_auction(&auction_id);

    assert!(auction.is_some(), "auction should exist");

    let auction = auction.unwrap();

    assert!(auction.owner == bidder, "Auction owner should exist");
    assert!(
        auction.auction_status == AuctionStatus::Completed,
        "Auction status should match"
    );
}

#[test]
fn test_end_regular_auction_when_inactivity_seconds_elapsed() {
    let Auction {
        client,
        item_metadata,
        token,
        owner,
        token_admin,
        env,
        ..
    } = Auction::new();

    let auction_conditions = AuctionConditionsBuilder::new(AuctionType::Regular, 1000, 100)
        .on_inactivity_seconds(500)
        .build();

    client.create_auction(&owner, &token.address, &item_metadata, &auction_conditions);

    let auction_id = 1;

    let bidder = Address::generate(&env);
    let bid_amount = 1000;

    token_admin.mint(&bidder, &bid_amount);
    assert_eq!(token.balance(&bidder), 1000);

    client.make_bid(&auction_id, &bidder, &bid_amount);

    // Move to inactivity seconds
    env.ledger().set_timestamp(505);

    client.end_auction(&auction_id);

    let auction = client.get_auction(&auction_id);

    assert!(auction.is_some(), "auction should exist");

    let auction = auction.unwrap();

    assert!(auction.owner == bidder, "Auction owner should exist");
    assert!(
        auction.auction_status == AuctionStatus::Completed,
        "Auction status should match"
    );
}

#[test]
fn test_end_regular_auction_when_sequence_no_elapsed() {
    let Auction {
        client,
        item_metadata,
        token,
        owner,
        token_admin,
        env,
        ..
    } = Auction::new();

    let auction_conditions = AuctionConditionsBuilder::new(AuctionType::Regular, 1000, 100)
        .on_fixed_sequence_number(500)
        .build();

    client.create_auction(&owner, &token.address, &item_metadata, &auction_conditions);

    let auction_id = 1;

    let bidder = Address::generate(&env);
    let bid_amount = 1000;

    token_admin.mint(&bidder, &bid_amount);
    assert_eq!(token.balance(&bidder), 1000);

    client.make_bid(&auction_id, &bidder, &bid_amount);

    // Move to sequence number
    env.ledger().set_sequence_number(505);

    client.end_auction(&auction_id);

    let auction = client.get_auction(&auction_id);

    assert!(auction.is_some(), "auction should exist");

    let auction = auction.unwrap();

    assert!(auction.owner == bidder, "Auction owner should exist");
    assert!(
        auction.auction_status == AuctionStatus::Completed,
        "Auction status should match"
    );
}

#[test]
fn test_end_regular_auction_when_min_no_of_participants_reached() {
    let Auction {
        client,
        item_metadata,
        token,
        owner,
        token_admin,
        env,
        ..
    } = Auction::new();

    let auction_conditions = AuctionConditionsBuilder::new(AuctionType::Regular, 1000, 100)
        .on_minimum_participants(1)
        .build();

    client.create_auction(&owner, &token.address, &item_metadata, &auction_conditions);

    let auction_id = 1;

    let bidder = Address::generate(&env);
    let bid_amount = 1000;

    token_admin.mint(&bidder, &bid_amount);
    assert_eq!(token.balance(&bidder), 1000);

    client.make_bid(&auction_id, &bidder, &bid_amount);

    client.end_auction(&auction_id);

    let auction = client.get_auction(&auction_id);

    assert!(auction.is_some(), "auction should exist");

    let auction = auction.unwrap();

    assert!(auction.owner == bidder, "Auction owner should exist");
    assert!(
        auction.auction_status == AuctionStatus::Completed,
        "Auction status should match"
    );
}

#[test]
fn test_end_regular_auction_when_condition_not_met_but_time_exceeded() {
    let Auction {
        client,
        item_metadata,
        token,
        owner,
        token_admin,
        env,
        ..
    } = Auction::new();

    let auction_conditions = AuctionConditionsBuilder::new(AuctionType::Regular, 1000, 100)
        .on_fixed_sequence_number(15)
        .on_inactivity_seconds(100)
        .on_maximum_participants(1000)
        .on_minimum_participants(50)
        .on_bid_count(10)
        .on_target_price(100000)
        .on_fixed_sequence_number(49)
        .build();

    client.create_auction(&owner, &token.address, &item_metadata, &auction_conditions);

    let auction_id = 1;

    let bidder = Address::generate(&env);
    let bid_amount = 1000;

    token_admin.mint(&bidder, &bid_amount);
    assert_eq!(token.balance(&bidder), 1000);

    client.make_bid(&auction_id, &bidder, &bid_amount);

    // after end time
    env.ledger().set_timestamp(1001);

    client.end_auction(&auction_id);

    let auction = client.get_auction(&auction_id);

    assert!(auction.is_some(), "auction should exist");

    let auction = auction.unwrap();

    assert!(auction.owner == bidder, "Auction owner should exist");
    assert!(
        auction.auction_status == AuctionStatus::Completed,
        "Auction status should match"
    );
}

#[test]
fn test_end_regular_auction_when_no_bids() {
    let Auction {
        client,
        item_metadata,
        token,
        owner,
        env,
        ..
    } = Auction::new();

    let auction_conditions = AuctionConditionsBuilder::new(AuctionType::Regular, 1000, 100).build();

    client.create_auction(&owner, &token.address, &item_metadata, &auction_conditions);

    let auction_id = 1;

    // after end time
    env.ledger().set_timestamp(1001);

    client.end_auction(&auction_id);

    let auction = client.get_auction(&auction_id);

    assert!(auction.is_some(), "auction should exist");

    let auction = auction.unwrap();

    // transfer of ownership not made
    assert!(auction.owner == owner, "Auction owner should match");
    assert!(
        auction.auction_status == AuctionStatus::Completed,
        "Auction status should match"
    );
}
