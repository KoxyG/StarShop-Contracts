use soroban_sdk::{symbol_short, Env, Map, Symbol, Vec};
use crate::vote::VoteManager;
use crate::types::VoteType;

pub struct RankingCalculator;

const TRENDING_WINDOW: u64 = 48 * 60 * 60; // 48 hours in seconds

impl RankingCalculator {
    pub fn init(env: &Env) {
        let rankings: Map<Symbol, i32> = Map::new(env);
        env.storage().instance().set(&symbol_short!("rankings"), &rankings);
    }

    pub fn update_ranking(env: &Env, product_id: Symbol) {
        let score = Self::calculate_score(env, product_id);
        
        let mut rankings: Map<Symbol, i32> = env.storage().instance().get(&symbol_short!("rankings")).unwrap();
        rankings.set(product_id, score);
        env.storage().instance().set(&symbol_short!("rankings"), &rankings);
    }

    pub fn get_score(env: &Env, product_id: Symbol) -> i32 {
        let rankings: Map<Symbol, i32> = env.storage().instance().get(&symbol_short!("rankings")).unwrap();
        rankings.get(product_id).unwrap_or(0)
    }

    pub fn get_trending(env: &Env) -> Vec<Symbol> {
        let rankings: Map<Symbol, i32> = env.storage().instance().get(&symbol_short!("rankings")).unwrap();
        let mut products: Vec<(Symbol, i32)> = Vec::new(env);

        // Convert map to vec for sorting
        for (id, score) in rankings.iter() {
            products.push_back((id, score));
        }

        // Sort by score
        products.sort_by(|a, b| b.1.cmp(&a.1));

        // Return only product IDs
        let mut result = Vec::new(env);
        for (id, _) in products.iter() {
            result.push_back(*id);
        }

        result
    }

    fn calculate_score(env: &Env, product_id: Symbol) -> i32 {
        let product = VoteManager::get_product(env, product_id)
            .expect("Product should exist");
            
        let now = env.ledger().timestamp();
        let age_hours = (now - product.created_at) / 3600;

        // Calculate base score from votes
        let mut base_score = 0i32;
        for vote in product.votes.values() {
            match vote.vote_type {
                VoteType::Upvote => base_score += 1,
                VoteType::Downvote => base_score -= 1,
            }
        }

        // Count recent votes for trending factor
        let recent_votes = product.votes.values()
            .filter(|vote| now - vote.timestamp <= TRENDING_WINDOW)
            .count() as i32;

        // Apply time decay and add trending bonus
        base_score / (1 + (age_hours / 24) as i32) + (recent_votes / 2)
    }
}