#![cfg(test)]

use soroban_sdk::{symbol_short, testutils::Address as _, Address, Env, Map, Symbol};

use crate::types::Product;
use super::*;


#[test]
fn test_raffle_initialization() {
    let env = Env::default();
    ProductVoting::init(env.clone());

    // Verify initial state
    let products: Map<Symbol, Product> = env.storage().instance().get(&symbol_short!("products")).unwrap();
    assert!(products.is_empty());
}

#[test]
fn test_create_product() {
    let env = Env::default();
    ProductVoting::init(env.clone());

    let product_id = symbol_short!("product1");
    let product_name = symbol_short!("Product1");

    ProductVoting::create_product(env.clone(), product_id.clone(), product_name.clone()).unwrap();

    // Verify product creation
    let products: Map<Symbol, Product> = env.storage().instance().get(&symbol_short!("products")).unwrap();
    let product = products.get(product_id.clone()).unwrap();
    assert_eq!(product.id, product_id);
    assert_eq!(product.name, product_name);
}

#[test]
fn test_cast_vote() {
    let env = Env::default();
    ProductVoting::init(env.clone());

    let product_id = symbol_short!("product1");
    let product_name = symbol_short!("Product1");
    ProductVoting::create_product(env.clone(), product_id.clone(), product_name.clone()).unwrap();

    let voter = Address::from_str(&env, "voter1");
    ProductVoting::cast_vote(env.clone(), product_id.clone(), VoteType::Upvote, voter.clone()).unwrap();

    // Verify vote casting
    let products: Map<Symbol, Product> = env.storage().instance().get(&symbol_short!("products")).unwrap();
    let product = products.get(product_id.clone()).unwrap();
    let vote = product.votes.get(voter.clone()).unwrap();
    assert_eq!(vote.vote_type, VoteType::Upvote);
assert_eq!(vote.voter, voter);
}

#[test]
fn test_get_product_score() {
    let env = Env::default();
    ProductVoting::init(env.clone());

    let product_id = symbol_short!("product1");
    let product_name = symbol_short!("Product1");
    ProductVoting::create_product(env.clone(), product_id.clone(), product_name.clone()).unwrap();

    let voter = Address::from_str(&env, "voter1");
    ProductVoting::cast_vote(env.clone(), product_id.clone(), VoteType::Upvote, voter.clone()).unwrap();

    // Verify product score
    let score = ProductVoting::get_product_score(env.clone(), product_id.clone());
    assert_eq!(score, 1);
}

#[test]
fn test_get_trending_products() {
    let env = Env::default();
    ProductVoting::init(env.clone());

    let product_id1 = symbol_short!("product1");
    let product_name1 = symbol_short!("Product_1");
    ProductVoting::create_product(env.clone(), product_id1.clone(), product_name1.clone()).unwrap();

    let product_id2 = symbol_short!("product2");
    let product_name2 = symbol_short!("Product_2");
    ProductVoting::create_product(env.clone(), product_id2.clone(), product_name2.clone()).unwrap();

    let voter1 = Address::from_str(&env, "voter1");
    let voter2 = Address::from_str(&env, "voter2");
    ProductVoting::cast_vote(env.clone(), product_id1.clone(), VoteType::Upvote, voter1.clone()).unwrap();
    ProductVoting::cast_vote(env.clone(), product_id2.clone(), VoteType::Upvote, voter2.clone()).unwrap();
    ProductVoting::cast_vote(env.clone(), product_id2.clone(), VoteType::Upvote, voter1.clone()).unwrap();

    // Verify trending products
    let trending_products = ProductVoting::get_trending_products(env.clone());
    assert_eq!(trending_products.len(), 2);
    assert_eq!(trending_products.get(0).unwrap(), product_id2);
    assert_eq!(trending_products.get(1).unwrap(), product_id1);
}