#![no_std]
use soroban_sdk::{contract, contractimpl, Address, Env, Symbol, Vec};

pub mod limits;
pub mod ranking;
pub mod types;
pub mod vote;
pub mod test;

use limits::VoteLimiter;
use ranking::RankingCalculator;
use types::{Error, VoteType};
use vote::VoteManager;

pub trait ProductVotingTrait {
    fn init(env: Env);
    fn create_product(env: Env, id: Symbol, name: Symbol) -> Result<(), Error>;
    fn cast_vote(
        env: Env,
        product_id: Symbol,
        vote_type: VoteType,
        voter: Address,
    ) -> Result<(), Error>;
    fn get_product_score(env: Env, product_id: Symbol) -> i32;
    fn get_trending_products(env: Env) -> Vec<Symbol>;
}

#[contract]
pub struct ProductVoting;

#[contractimpl]
impl ProductVotingTrait for ProductVoting {
    fn init(env: Env) {
        VoteManager::init(&env);
        RankingCalculator::init(&env);
        VoteLimiter::init(&env);
    }

    fn create_product(env: Env, id: Symbol, name: Symbol) -> Result<(), Error> {
        VoteManager::create_product(&env, id, name)
    }

    fn cast_vote(
        env: Env,
        product_id: Symbol,
        vote_type: VoteType,
        voter: Address,
    ) -> Result<(), Error> {
        // Check vote limits first
        VoteLimiter::check_limits(&env, &voter)?;

        // Cast the vote - clone product_id since we'll use it again
        VoteManager::cast_vote(&env, product_id.clone(), vote_type, voter)?;

        // Update rankings
        RankingCalculator::update_ranking(&env, product_id);

        Ok(())
    }

    fn get_product_score(env: Env, product_id: Symbol) -> i32 {
        RankingCalculator::get_score(&env, product_id)
    }

    fn get_trending_products(env: Env) -> Vec<Symbol> {
        RankingCalculator::get_trending(&env)
    }
}
