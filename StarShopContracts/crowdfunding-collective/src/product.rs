use crate::types::*;
use soroban_sdk::{Address, Env, String, Vec};

pub fn create_product(
    env: Env,
    creator: Address,
    name: String,
    description: String,
    funding_goal: u64,
    deadline: u64, // Changed from &u64
    reward_tiers: Vec<RewardTier>,
    milestones: Vec<Milestone>,
) -> u32 {
    creator.require_auth();

    // Validate inputs
    if funding_goal == 0 {
        panic!("Funding goal must be greater than zero");
    }
    if deadline <= env.ledger().timestamp() {
        panic!("Deadline must be in the future");
    }

    // Get next product ID
    let product_id = next_product_id(&env);

    // Create product
    let product = Product {
        id: product_id,
        creator,
        name,
        description,
        funding_goal,
        deadline,
        status: ProductStatus::Active,
        total_funded: 0,
    };

    // Store product
    env.storage()
        .instance()
        .set(&DataKey::Products(product_id), &product);

    // Store reward tiers and milestones
    env.storage()
        .instance()
        .set(&DataKey::Rewards(product_id), &reward_tiers);
    env.storage()
        .instance()
        .set(&DataKey::Milestones(product_id), &milestones);

    // Initialize contributions
    let contributions: Vec<Contribution> = Vec::new(&env);
    env.storage()
        .instance()
        .set(&DataKey::Contributions(product_id), &contributions);
    env.storage()
        .instance()
        .set(&DataKey::ContributionsTotal(product_id), &0u64);

    product_id
}

pub fn get_product(env: Env, product_id: u32) -> Product {
    env.storage()
        .instance()
        .get(&DataKey::Products(product_id))
        .unwrap_or_else(|| panic!("Product not found"))
}

fn next_product_id(env: &Env) -> u32 {
    let product_id = env
        .storage()
        .instance()
        .get(&DataKey::NextProductId)
        .unwrap_or(1u32);
    env.storage()
        .instance()
        .set(&DataKey::NextProductId, &(product_id + 1));
    product_id
}
