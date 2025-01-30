use crate::datatype::{
    DataKeys, FollowCategory, FollowData, FollowError,
};
use crate::interface::FollowOperations;
use soroban_sdk::{Address, Env, Vec};

// This is a struct that implements the FollowOperations trait
#[allow(dead_code)]
pub struct FollowSystem;

// This is a constant for the default follow limit
const DEFAULT_FOLLOW_LIMIT: u32 = 100;

// This implements the FollowOperations trait for the FollowSystem struct
impl FollowOperations for FollowSystem {
    // This function allows a user to follow a product
    fn follow_product(
        env: Env,
        user: Address,
        product_id: u128,
        categories: Vec<FollowCategory>,
    ) -> Result<(), FollowError> {
        // This requires that the user is authorized to perform this action
        user.require_auth();
       
        // This gets the current follow list for the user
        let follow_key = DataKeys::FollowList(user.clone());
        let mut follows: Vec<FollowData> = env
            .storage()
            .persistent()
            .get(&follow_key)
            .unwrap_or_else(|| Vec::new(&env));

        // This checks if the user has reached their follow limit
        let limit_key = DataKeys::FollowLimit(user.clone());
        let follow_limit: u32 = env
            .storage()
            .persistent()
            .get(&limit_key)
            .unwrap_or(DEFAULT_FOLLOW_LIMIT);

        if follows.len() >= follow_limit as u32 {
            // This returns an error if the user has reached their follow limit
            return Err(FollowError::FollowLimitExceeded);
        }

        // This checks if the user is already following the product
        if follows.iter().any(|f| f.product_id == product_id) {
            // This returns an error if the user is already following the product
            return Err(FollowError::AlreadyFollowing);
        }

        // This creates a new follow data
        let follow_data = FollowData {
            product_id,
            categories: categories.clone(),
            timestamp: env.ledger().timestamp(),
            expires_at: None,
        };

        // This adds the new follow data to the follow list
        follows.push_back(follow_data);
        env.storage().persistent().set(&follow_key, &follows);

        // This updates the category tracking for the user
        let category_key = DataKeys::FollowCategory(user.clone());
        let mut user_categories: Vec<FollowCategory> = env
            .storage()
            .persistent()
            .get(&category_key)
            .unwrap_or_else(|| Vec::new(&env));

        for category in categories {
            if !user_categories.contains(&category) {
                user_categories.push_back(category);
            }
        }
        env.storage()
            .persistent()
            .set(&category_key, &user_categories);

        // This returns a successful result
        Ok(())
    }

    // This function allows a user to unfollow a product
    fn unfollow_product(env: Env, user: Address, product_id: u128) -> Result<(), FollowError> {
        // This requires that the user is authorized to perform this action
        user.require_auth();

        // This gets the current follow list for the user
        let follow_key = DataKeys::FollowList(user.clone());
        let follows: Vec<FollowData> = env
            .storage()
            .persistent()
            .get(&follow_key)
            .unwrap_or_else(|| Vec::new(&env));

        // This manually filters out the product to unfollow
        let mut updated_follows = Vec::new(&env);
        let mut found = false;

        for follow in follows.iter() {
            if follow.product_id != product_id {
                updated_follows.push_back(follow.clone());
            } else {
                found = true;
            }
        }

        // This returns an error if the user is not following the product
        if !found {
            return Err(FollowError::NotFollowing);
        }

        // This updates the storage with the new list
        env.storage()
            .persistent()
            .set(&follow_key, &updated_follows);

        // This returns a successful result
        Ok(())
    }

    // This function gets the followed products for a user
    fn get_followed_products(env: Env, user: Address) -> Result<Vec<FollowData>, FollowError> {
        // This gets the current follow list for the user
        let follow_key = DataKeys::FollowList(user.clone());
        let follows: Vec<FollowData> = env
            .storage()
            .persistent()
            .get(&follow_key)
            .unwrap_or_else(|| Vec::new(&env));

        // This returns the followed products
        Ok(follows)
    }
}
