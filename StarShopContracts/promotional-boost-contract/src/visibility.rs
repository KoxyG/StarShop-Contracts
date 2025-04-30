use soroban_sdk::{Env, Address, Map, Vec, Symbol, contracttype, symbol_short};

#[derive(Clone)]
#[contracttype]
pub struct BoostVisibility {
    pub product_id: u64,
    pub seller: Address,
    pub start_time: u64,
    pub end_time: u64,
    pub price_paid: u64,
}

#[derive(Clone)]
#[contracttype]
pub struct VisibilityManager {
    pub boosts: Map<u64, BoostVisibility>,     // product_id → visibility info
}

impl VisibilityManager {

    const STORAGE_KEY: Symbol = symbol_short!("visibile");

    pub fn new(env: &Env) -> Self {
        Self {
            boosts: Map::new(env),
        }
    }

    /// Add visibility boost info for a product
    pub fn flag_product_as_boosted(
        &mut self,
        product_id: u64,
        seller: Address,
        start_time: u64,
        duration: u64,
        price_paid: u64,
    ) {
        let end_time = start_time + duration;
        let boost = BoostVisibility {
            product_id,
            seller,
            start_time,
            end_time,
            price_paid,
        };

        self.boosts.set(product_id, boost);
    }

    /// Remove expired boosts based on current time
    pub fn remove_expired(&mut self, current_time: u64) {
        let keys = self.boosts.keys();
        for pid in keys.iter() {
            if let Some(info) = self.boosts.get(pid) {
                if current_time >= info.end_time {
                    self.boosts.remove(pid);
                }
            }
        }
    }

    /// Returns `true` if the product is currently boosted
    pub fn is_boosted(&self, product_id: u64, current_time: u64) -> bool {
        if let Some(info) = self.boosts.get(product_id) {
            return current_time < info.end_time;
        }
        false
    }

    /// Returns list of all boosted product IDs
    pub fn get_active_boosts(&self, current_time: u64) -> Vec<u64> {
        let mut result = Vec::new(&self.boosts.env());
        for pid in self.boosts.keys().iter() {
            if let Some(info) = self.boosts.get(pid) {
                if current_time < info.end_time {
                    result.push_back(info.product_id);
                }
            }
        }
        result
    }

    /// Returns boost metadata for a product
    pub fn get_boost_info(&self, product_id: u64) -> Option<BoostVisibility> {
        self.boosts.get(product_id)
    }

    pub fn save(&self, env: &Env) {
        env.storage().instance().set(&Self::STORAGE_KEY, self);
    }

    pub fn load_or_default(env: &Env) -> Self {
        env.storage().instance().get(&Self::STORAGE_KEY).unwrap_or(Self::new(env))
    }
}
