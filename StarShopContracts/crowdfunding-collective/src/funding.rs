use crate::types::*;
use soroban_sdk::{Address, Env, Symbol, Vec};

pub fn contribute(env: Env, contributor: Address, product_id: u32, amount: u64) {
    contributor.require_auth();

    let mut product = get_product(&env, product_id);
    if product.status != ProductStatus::Active {
        panic!("Product is not active");
    }
    if env.ledger().timestamp() > product.deadline {
        panic!("Funding period has ended");
    }
    if amount == 0 {
        panic!("Contribution must be greater than zero");
    }

    // Check if contribution would exceed funding goal
    let total_funded = env
        .storage()
        .instance()
        .get(&DataKey::ContributionsTotal(product_id))
        .unwrap_or(0u64);
    let new_total = total_funded + amount;
    if new_total > product.funding_goal {
        panic!("Contribution would exceed funding goal");
    }

    // Update contributions
    let mut contributions: Vec<Contribution> = env
        .storage()
        .instance()
        .get(&DataKey::Contributions(product_id))
        .unwrap_or_else(|| Vec::new(&env));
    contributions.push_back(Contribution {
        contributor: contributor.clone(),
        amount,
        timestamp: env.ledger().timestamp(),
    });
    env.storage()
        .instance()
        .set(&DataKey::Contributions(product_id), &contributions);

    // Update total funded
    env.storage()
        .instance()
        .set(&DataKey::ContributionsTotal(product_id), &new_total);

    // Update product
    product.total_funded = new_total;
    if product.total_funded >= product.funding_goal {
        product.status = ProductStatus::Funded;
    }
    env.storage()
        .instance()
        .set(&DataKey::Products(product_id), &product);

    // Emit event with explicit type annotation
    let event_data: i128 = amount as i128;
    env.events().publish(
        (Symbol::new(&env, "Contribution"), product_id, contributor),
        event_data,
    );
}

pub fn distribute_funds(env: Env, product_id: u32) {
    let product = get_product(&env, product_id);
    if product.status != ProductStatus::Funded {
        panic!("Product is not funded");
    }

    let milestones: Vec<Milestone> = env
        .storage()
        .instance()
        .get(&DataKey::Milestones(product_id))
        .unwrap_or_else(|| Vec::new(&env));
    for milestone in milestones.iter() {
        if !milestone.completed {
            panic!("Not all milestones are completed");
        }
    }

    let mut product = get_product(&env, product_id);
    product.status = ProductStatus::Completed;
    env.storage()
        .instance()
        .set(&DataKey::Products(product_id), &product);

    // Emit event with explicit type annotation
    let event_data: i128 = product.total_funded as i128;
    env.events().publish(
        (Symbol::new(&env, "FundsDistributed"), product_id),
        event_data,
    );
}

pub fn refund_contributors(env: Env, product_id: u32) {
    let product = get_product(&env, product_id);
    if product.status != ProductStatus::Active {
        panic!("Product is not active");
    }
    if env.ledger().timestamp() <= product.deadline {
        panic!("Funding period has not ended");
    }

    let mut product = get_product(&env, product_id);
    product.status = ProductStatus::Failed;
    env.storage()
        .instance()
        .set(&DataKey::Products(product_id), &product);

    let contributions: Vec<Contribution> = env
        .storage()
        .instance()
        .get(&DataKey::Contributions(product_id))
        .unwrap_or_else(|| Vec::new(&env));
    for contribution in contributions.iter() {
        // Emit event with explicit type annotation
        let event_data: i128 = contribution.amount as i128;
        env.events().publish(
            (
                Symbol::new(&env, "Refund"),
                product_id,
                contribution.contributor,
            ),
            event_data,
        );
    }

    env.storage().instance().set(
        &DataKey::Contributions(product_id),
        &Vec::<Contribution>::new(&env),
    );
    env.storage()
        .instance()
        .set(&DataKey::ContributionsTotal(product_id), &0u64);
}

fn get_product(env: &Env, product_id: u32) -> Product {
    env.storage()
        .instance()
        .get(&DataKey::Products(product_id))
        .unwrap_or_else(|| panic!("Product not found"))
}
