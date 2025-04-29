mod slots;
mod payments;
mod visibility;

use slots::{SlotManager, Slot};
use payments::PaymentManager;
use visibility::VisibilityManager;

pub struct BoostContract {
    slot_manager: SlotManager,
    payment_manager: PaymentManager,
    visibility_manager: VisibilityManager,
}

impl BoostContract {
    pub fn new(sender_secret: &str) -> Self {
        BoostContract {
            slot_manager: SlotManager::new(),
            payment_manager: PaymentManager::new(sender_secret),
            visibility_manager: VisibilityManager::new(),
        }
    }

    /// Entry point to purchase a boost (async version)
    pub async fn purchase_boost(
        &mut self,
        seller_id: String,
        product_id: String,
        xlm_amount: String,
        duration: u64,
    ) -> Result<(), String> {
        // Step 1: Validate payment
        self.payment_manager
            .process_payment(&seller_id, &xlm_amount)
            .await?;

        // Step 2: Allocate slot
        let slot = self.slot_manager.allocate_slot(seller_id.clone(), duration)?;

        // Step 3: Apply visibility boost
        self.visibility_manager.boost_product(slot, product_id);

        Ok(())
    }
}
