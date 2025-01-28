#![no_std]
use soroban_sdk::{contract, contractimpl, Symbol, Env, Vec};

pub mod vote;
pub mod ranking;
pub mod limits;
pub mod types;

use types::{VoteType, Error};
use vote::VoteManager;
use ranking::RankingCalculator;
use limits::VoteLimiter;

pub trait ProductVotingTrait {
    fn init(env: Env);
    fn create_product(env: Env, id: Symbol, name: Symbol) -> Result<(), Error>;
    fn cast_vote(env: Env, product_id: Symbol, vote_type: VoteType) -> Result<(), Error>;
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

    fn cast_vote(env: Env, product_id: Symbol, vote_type: VoteType) -> Result<(), Error> {
        // Check vote limits first
        VoteLimiter::check_limits(&env, &env.invoker())?;
        
        // Cast the vote
        VoteManager::cast_vote(&env, product_id, vote_type, env.invoker())?;
        
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