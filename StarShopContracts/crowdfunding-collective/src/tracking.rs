use crate::types::*;
use soroban_sdk::{Address, Env, Vec};

pub fn update_milestone(env: Env, creator: Address, product_id: u32, milestone_id: u32) {
    creator.require_auth();

    let product: Product = env
        .storage()
        .instance()
        .get(&DataKey::Products(product_id))
        .unwrap_or_else(|| panic!("Product not found"));

    if product.creator != creator {
        panic!("Only the creator can update milestones");
    }
    if product.status != ProductStatus::Funded {
        panic!("Product is not funded");
    }

    let mut milestones: Vec<Milestone> = env
        .storage()
        .instance()
        .get(&DataKey::Milestones(product_id))
        .unwrap_or_else(|| Vec::new(&env));

    let mut milestone = milestones.get(milestone_id).unwrap();
    if milestone.completed {
        panic!("Milestone already completed");
    }

    milestone.completed = true;
    milestones.set(milestone_id, milestone);
    env.storage()
        .instance()
        .set(&DataKey::Milestones(product_id), &milestones);

    env.events()
        .publish(("MilestoneCompleted", product_id), milestone_id);
}

pub fn get_contributions(env: Env, product_id: u32) -> Vec<Contribution> {
    env.storage()
        .instance()
        .get(&DataKey::Contributions(product_id))
        .unwrap_or_else(|| Vec::new(&env))
}

pub fn get_milestones(env: Env, product_id: u32) -> Vec<Milestone> {
    env.storage()
        .instance()
        .get(&DataKey::Milestones(product_id))
        .unwrap_or_else(|| Vec::new(&env))
}
