use soroban_sdk::{symbol_short, Address, Env, Map, Symbol};
use crate::types::{Error, Product, Vote, VoteType};

pub struct VoteManager;

impl VoteManager {
    pub fn init(env: &Env) {
        let products: Map<Symbol, Product> = Map::new(env);
        env.storage().instance().set(&symbol_short!("products"), &products);
    }

    pub fn create_product(env: &Env, id: Symbol, name: Symbol) -> Result<(), Error> {
        let mut products: Map<Symbol, Product> = env.storage().instance().get(&symbol_short!("products")).unwrap();
        
        if products.contains_key(id.clone()) {
            return Err(Error::ProductExists);
        }

        let product = Product {
            id: id.clone(),
            name,
            created_at: env.ledger().timestamp(),
            votes: Map::new(env),
        };

        products.set(id, product);
        env.storage().instance().set(&symbol_short!("products"), &products);
        Ok(())
    }

    pub fn cast_vote(
        env: &Env,
        product_id: Symbol,
        vote_type: VoteType,
        voter: Address,
    ) -> Result<(), Error> {
        let mut products: Map<Symbol, Product> = env.storage().instance().get(&symbol_short!("products")).unwrap();
        
        let mut product = products.get(product_id.clone())
            .ok_or(Error::ProductNotFound)?;
            
        let now = env.ledger().timestamp();

        // Check voting period (30 days)
        if now - product.created_at > 30 * 24 * 60 * 60 {
            return Err(Error::VotingPeriodEnded);
        }

        // Handle existing votes
        if let Some(existing_vote) = product.votes.get(voter.clone()) {
            // Check reversal window (24 hours)
            if now - existing_vote.timestamp > 24 * 60 * 60 {
                return Err(Error::ReversalWindowExpired);
            }
        }

        // Record vote
        let vote = Vote {
            vote_type,
            timestamp: now,
            voter: voter.clone(),
        };

        product.votes.set(voter, vote);
        products.set(product_id, product);
        env.storage().instance().set(&symbol_short!("products"), &products);

        Ok(())
    }

    pub fn get_product(env: &Env, product_id: Symbol) -> Option<Product> {
        let products: Map<Symbol, Product> = env.storage().instance().get(&symbol_short!("products")).unwrap();
        products.get(product_id)
    }
}