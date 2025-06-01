#![no_std]

use soroban_sdk::{contract, contractimpl, Address, Env, Symbol, Vec};

mod payments;
mod slots;
mod visibility;

use payments::PaymentProcessor;
use slots::{SlotManager, SlotResult};
use visibility::VisibilityManager;

#[contract]
pub struct PromotionBoostContract;

#[contractimpl]
impl PromotionBoostContract {
    /// Initialize the contract with default slot limits
    pub fn initialize(env: Env) {
        let mut slot_manager = SlotManager::load_or_default(&env);
        
        // Set default max slots for common categories
        slot_manager.set_max_slots(Symbol::new(&env, "electronics"), 3);
        slot_manager.set_max_slots(Symbol::new(&env, "clothing"), 3);
        slot_manager.set_max_slots(Symbol::new(&env, "books"), 3);
        slot_manager.set_max_slots(Symbol::new(&env, "home"), 3);
        
        slot_manager.save(&env);
    }

    /// Set maximum slots for a category (admin function)
    pub fn set_category_max_slots(env: Env, category: Symbol, max_slots: u32) {
        let mut slot_manager = SlotManager::load_or_default(&env);
        slot_manager.set_max_slots(category, max_slots);
        slot_manager.save(&env);
    }

    /// Seller calls this to boost a product
    pub fn boost_product(
        env: Env,
        seller_address: Address,
        category: Symbol,
        product_id: u64,
        duration_secs: u64,
        payment_amount: i128,
    ) {
        let now = env.ledger().timestamp();

        let seller_address_clone = seller_address.clone();

        // 1. Calculate required price
        let required_price = PaymentProcessor::calculate_price(duration_secs);
        if payment_amount < required_price {
            panic!("Insufficient payment for duration");
        }

        // 2. Collect XLM from seller
        PaymentProcessor::collect_payment(&env, &seller_address, payment_amount, required_price)
            .expect("XLM payment failed");

        // 3. Access or create slot manager
        // Generate unique slot ID using a combination that's more likely to be unique
        let slot_id = now.wrapping_mul(1000000).wrapping_add(product_id).wrapping_add(env.ledger().sequence() as u64);
        let mut slot_manager = SlotManager::load_or_default(&env);

        let slot_result = slot_manager.add_slot(
            &env,
            slot_id,
            product_id,
            seller_address.clone(),
            category.clone(),
            duration_secs,
            payment_amount.try_into().expect("Amount conversion failed"),
            now,
        );

        // Handle the slot result
        match slot_result {
            SlotResult::Rejected => {
                // Slot was rejected due to limits and insufficient bid
                // Refund the payment
                PaymentProcessor::refund_payment(&env, &seller_address, payment_amount)
                    .expect("Refund failed");
                panic!("Slot limit reached and bid was not high enough");
            }
            SlotResult::Added => {
                // Slot was successfully added
                // Emit event for slot added
                env.events().publish(
                    (Symbol::new(&env, "boost_slot_added"), seller_address.clone()),
                    (slot_id, category.clone(), product_id, duration_secs, payment_amount),
                );

                // Update visibility logic for successful add
                let mut visibility = VisibilityManager::load_or_default(&env);
                visibility.flag_product_as_boosted(
                    product_id,
                    seller_address.clone(),
                    now,
                    duration_secs,
                    payment_amount.try_into().expect("Amount conversion failed"),
                );
                visibility.remove_expired(now);
                visibility.save(&env);

                // Emit event for visibility change
                env.events().publish(
                    (Symbol::new(&env, "visibility_boosted"), seller_address_clone),
                    (product_id, category),
                );
            }
            SlotResult::Replaced(_replaced_slot_id, replaced_slot) => {
                // Slot replaced another slot
                // Remove the replaced product from visibility first
                let mut visibility = VisibilityManager::load_or_default(&env);
                visibility.boosts.remove(replaced_slot.product_id);
                
                // Refund the replaced slot's payment
                PaymentProcessor::refund_payment(
                    &env,
                    &replaced_slot.seller,
                    replaced_slot.price_paid.into(),
                )
                .expect("Refund failed");

                // Emit event for replaced slot
                env.events().publish(
                    (Symbol::new(&env, "boost_slot_replaced"), replaced_slot.seller.clone()),
                    (replaced_slot.product_id, replaced_slot.price_paid),
                );

                // Add the new product to visibility
                visibility.flag_product_as_boosted(
                    product_id,
                    seller_address.clone(),
                    now,
                    duration_secs,
                    payment_amount.try_into().expect("Amount conversion failed"),
                );
                
                // Clean up expired entries
                visibility.remove_expired(now);
                visibility.save(&env);

                // Emit event for new slot added
                env.events().publish(
                    (Symbol::new(&env, "boost_slot_added"), seller_address.clone()),
                    (slot_id, category.clone(), product_id, duration_secs, payment_amount),
                );

                // Emit event for visibility change
                env.events().publish(
                    (Symbol::new(&env, "visibility_boosted"), seller_address_clone),
                    (product_id, category),
                );
            }
        }

        // Save updated slot state
        slot_manager.save(&env);
    }

    /// View if a product is currently boosted
    pub fn is_boosted(env: Env, product_id: u64) -> bool {
        let now = env.ledger().timestamp();
        let visibility = VisibilityManager::load_or_default(&env);
        visibility.is_boosted(product_id, now)
    }

    /// Return all active boosted product IDs
    pub fn get_boosted_list(env: Env) -> Vec<u64> {
        let now = env.ledger().timestamp();
        let visibility = VisibilityManager::load_or_default(&env);
        visibility.get_active_boosts(now)
    }

    /// Get current slot count for a category
    pub fn get_slot_count(env: Env, category: Symbol) -> u32 {
        let slot_manager = SlotManager::load_or_default(&env);
        let slot_ids = slot_manager.get_active_slots(category);
        slot_ids.len()
    }

    /// Admin clears expired slots (optional)
    pub fn cleanup_expired(env: Env, category: Symbol) {
        let now = env.ledger().timestamp();
        let mut slot_manager = SlotManager::load_or_default(&env);
        slot_manager.remove_expired_slots(&env, category, now);
        slot_manager.save(&env);

        let mut visibility = VisibilityManager::load_or_default(&env);
        visibility.remove_expired(now);
        visibility.save(&env);
    }
}

#[cfg(test)]
mod test;
