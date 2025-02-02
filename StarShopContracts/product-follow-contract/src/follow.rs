use crate::datatype::{DataKeys, FollowCategory, FollowData, FollowError};
use crate::interface::FollowOperations;
use soroban_sdk::{symbol_short, Address, Env, Symbol, Vec};

// This is a struct that implements the FollowOperations trait
#[allow(dead_code)]
pub struct FollowSystem;

#[allow(dead_code)]
pub const DEFAULT_FOLLOW_LIMIT: u32 = 100;

pub struct FollowManager<'a> {
    env: &'a Env,
}

impl<'a> FollowManager<'a> {
    pub fn new(env: &'a Env) -> Self {
        Self { env }
    }

    pub fn add_follower(
        &self,
        user: &Address,
        product_id: u32,
        categories: &Vec<FollowCategory>,
    ) -> Result<(), FollowError> {
        user.require_auth();

        // Validate follow limit for the product
        let product_followers_key = DataKeys::ProductFollowers(product_id);
        let mut product_followers: Vec<Address> = self
            .env
            .storage()
            .persistent()
            .get(&product_followers_key)
            .unwrap_or_else(|| Vec::new(self.env));
        if (product_followers.len() as u32) >= DEFAULT_FOLLOW_LIMIT {
            return Err(FollowError::FollowLimitExceeded);
        }

        // Validate categories
        for category in categories.iter() {
            match category {
                FollowCategory::PriceChange
                | FollowCategory::Restock
                | FollowCategory::SpecialOffer => continue,
            }
        }

        let key = DataKeys::FollowList(user.clone());
        let mut followers: Vec<FollowData> = self
            .env
            .storage()
            .persistent()
            .get(&key)
            .unwrap_or_else(|| Vec::new(self.env));

        // Check if user is already following
        if followers.iter().any(|f| f.product_id == product_id) {
            return Err(FollowError::AlreadyFollowing);
        }

        // Add new follower
        followers.push_back(FollowData {
            user: user.clone(),
            product_id,
            categories: categories.clone(),
            timestamp: self.env.ledger().timestamp(),
            expires_at: None,
        });

        // Store updated user followers
        self.env.storage().persistent().set(&key, &followers);

        // Add user to the product followers list
        product_followers.push_back(user.clone());
        self.env
            .storage()
            .persistent()
            .set(&product_followers_key, &product_followers);

        // Add user to the AllUsers list if not already present
        let all_users_key = DataKeys::AllUsers;
        let mut all_users: Vec<Address> = self
            .env
            .storage()
            .persistent()
            .get(&all_users_key)
            .unwrap_or_else(|| Vec::new(self.env));

        if !all_users.contains(user) {
            all_users.push_back(user.clone());
            self.env
                .storage()
                .persistent()
                .set(&all_users_key, &all_users);
        }

        Ok(())
    }

    pub fn get_followers(&self, user: &Address) -> Vec<FollowData> {
        let key = DataKeys::FollowList(user.clone());
        self.env
            .storage()
            .persistent()
            .get::<_, Vec<FollowData>>(&key)
            .unwrap_or_else(|| Vec::new(self.env))
    }

    pub fn remove_follower(&self, user: &Address, product_id: u32) -> Result<(), FollowError> {
        user.require_auth();

        let key = DataKeys::FollowList(user.clone());
        let mut followers: Vec<FollowData> = self
            .env
            .storage()
            .persistent()
            .get(&key)
            .unwrap_or_else(|| Vec::new(self.env));

        // Remove the follower
        let mut new_followers = Vec::new(self.env);
        for f in followers.iter() {
            if f.user != *user || f.product_id != product_id {
                new_followers.push_back(f.clone());
            }
        }
        followers = new_followers;

        // Store updated followers
        self.env.storage().persistent().set(&key, &followers);

        Ok(())
    }

    pub fn is_following(&self, user: &Address, _product_id: u32) -> bool {
        let follows = self.get_followers(user);
        follows.iter().any(|f| &f.user == user)
    }

    #[allow(dead_code)]
    pub fn get_follow_categories(&self, user: &Address, product_id: u32) -> Vec<FollowCategory> {
        let follows = self.get_followers(user);

        if let Some(follow_data) = follows
            .iter()
            .find(|f| &f.user == user && f.product_id == product_id)
        {
            follow_data.categories.clone()
        } else {
            Vec::new(self.env)
        }
    }

    #[allow(dead_code)]
    fn get_storage_key(&self, _product_id: u32) -> Symbol {
        symbol_short!("followers")
    }
}

// Implementation for FollowOperations
impl FollowOperations for FollowSystem {
    fn follow_product(
        env: Env,
        user: Address,
        product_id: u128,
        categories: Vec<FollowCategory>,
    ) -> Result<(), FollowError> {
        let product_id_u32: u32 = product_id
            .try_into()
            .map_err(|_| FollowError::InvalidProductId)?;
        let manager = FollowManager::new(&env);
        manager.add_follower(&user, product_id_u32, &categories)
    }

    fn unfollow_product(env: Env, user: Address, product_id: u128) -> Result<(), FollowError> {
        let product_id_u32: u32 = product_id
            .try_into()
            .map_err(|_| FollowError::InvalidProductId)?;
        let manager = FollowManager::new(&env);
        manager.remove_follower(&user, product_id_u32)
    }

    fn get_followed_products(env: Env, _user: Address) -> Result<Vec<FollowData>, FollowError> {
        let manager = FollowManager::new(&env);
        Ok(manager.get_followers(&_user))
    }
}
