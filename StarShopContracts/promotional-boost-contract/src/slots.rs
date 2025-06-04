use soroban_sdk::{contracttype, symbol_short, Address, Env, Map, Symbol, Vec};

#[derive(Clone, Debug, PartialEq)]
#[contracttype]
pub struct BoostSlot {
    pub product_id: u64,
    pub seller: Address,
    pub start_time: u64,
    pub end_time: u64,
    pub price_paid: u64,
}

#[derive(Clone, Debug, PartialEq)]
pub enum SlotResult {
    Added,                            // Slot was added to an available space
    Replaced(u64, BoostSlot),        // Slot replaced another slot (returns replaced slot ID and slot data)
    Rejected,                        // Slot was rejected due to limits and insufficient bid
}

#[derive(Clone, Debug)]
pub struct SlotParams {
    pub slot_id: u64,
    pub product_id: u64,
    pub seller: Address,
    pub category: Symbol,
    pub duration: u64,
    pub price_paid: u64,
    pub current_time: u64,
}

// Stores slots for each category
#[derive(Clone)]
#[contracttype]
pub struct SlotManager {
    pub slots: Map<u64, BoostSlot>,            // SlotID → Slot
    pub category_slots: Map<Symbol, Vec<u64>>, // Category → SlotIDs
    pub max_slots: Map<Symbol, u32>,           // Category → Max slot count
}

impl SlotManager {
    const STORAGE_KEY: Symbol = symbol_short!("slots");

    pub fn new(env: &Env) -> Self {
        Self {
            slots: Map::new(env),
            category_slots: Map::new(env),
            max_slots: Map::new(env),
        }
    }

    pub fn set_max_slots(&mut self, category: Symbol, count: u32) {
        self.max_slots.set(category, count);
    }

    pub fn add_slot(&mut self, env: &Env, params: SlotParams) -> SlotResult {
        let category_key = params.category.clone(); // Clone once for reuse

        // Remove expired slots first
        self.remove_expired_slots(env, category_key.clone(), params.current_time);

        // Get current slot list or empty
        let mut slot_ids = self
            .category_slots
            .get(category_key.clone())
            .unwrap_or(Vec::new(env));
        let max_slots = self.max_slots.get(category_key.clone()).unwrap_or(3); // default: 3

        if slot_ids.len() < max_slots {
            // There's room → add slot
            let slot = BoostSlot {
                product_id: params.product_id,
                seller: params.seller.clone(),
                start_time: params.current_time,
                end_time: params.current_time + params.duration,
                price_paid: params.price_paid,
            };
            self.slots.set(params.slot_id, slot);
            slot_ids.push_back(params.slot_id);
            self.category_slots.set(category_key, slot_ids);
            return SlotResult::Added;
        }

        // Full → check for lowest price replacement
        let mut lowest_slot_id: Option<u64> = None;
        let mut lowest_price: u64 = u64::MAX;

        // Find the slot with the lowest price
        for sid in slot_ids.iter() {
            if let Some(slot) = self.slots.get(sid) {
                if slot.price_paid < lowest_price {
                    lowest_price = slot.price_paid;
                    lowest_slot_id = Some(sid);
                }
            }
        }

        // Check if the new bid is higher than the lowest existing bid
        if params.price_paid > lowest_price {
            let replace_id = lowest_slot_id.unwrap();
            
            // Get the old slot data before removing it
            let replaced_slot = self.slots.get(replace_id).unwrap();
            
            // Remove the old slot from the slots map
            self.slots.remove(replace_id);

            // Create the new slot
            let new_slot = BoostSlot {
                product_id: params.product_id,
                seller: params.seller.clone(),
                start_time: params.current_time,
                end_time: params.current_time + params.duration,
                price_paid: params.price_paid,
            };
            self.slots.set(params.slot_id, new_slot);

            // Update the category slots list - replace the old slot ID with the new one
            let mut updated_ids = Vec::new(env);
            for id in slot_ids.iter() {
                if id != replace_id {
                    updated_ids.push_back(id);
                }
            }
            updated_ids.push_back(params.slot_id);
            self.category_slots.set(category_key, updated_ids);

            return SlotResult::Replaced(replace_id, replaced_slot);
        }

        // Did not win bid
        SlotResult::Rejected
    }

    pub fn remove_expired_slots(&mut self, env: &Env, category: Symbol, current_time: u64) {
        let category_key = category.clone();
        let slot_ids = self
            .category_slots
            .get(category_key)
            .unwrap_or(Vec::new(env));
        let mut active_ids = Vec::new(env);

        for slot_id in slot_ids.iter() {
            if let Some(slot) = self.slots.get(slot_id) {
                if current_time < slot.end_time {
                    active_ids.push_back(slot_id);
                } else {
                    self.slots.remove(slot_id); // Expired
                }
            }
        }

        self.category_slots.set(category, active_ids);
    }

    pub fn get_active_slots(&self, category: Symbol) -> Vec<u64> {
        self.category_slots
            .get(category)
            .unwrap_or(Vec::new(self.slots.env()))
    }

    pub fn get_slot(&self, slot_id: u64) -> Option<BoostSlot> {
        self.slots.get(slot_id)
    }

    pub fn save(&self, env: &Env) {
        env.storage().instance().set(&Self::STORAGE_KEY, self);
    }

    pub fn load_or_default(env: &Env) -> Self {
        env.storage()
            .instance()
            .get(&Self::STORAGE_KEY)
            .unwrap_or(Self::new(env))
    }
}
