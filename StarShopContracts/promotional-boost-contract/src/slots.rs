use std::collections::{HashMap, VecDeque};
use std::time::{SystemTime, Duration};

#[derive(Clone)]
pub struct Slot {
    pub seller_id: String,
    pub start_time: SystemTime,
    pub end_time: SystemTime,
    pub price: u64,
}

pub struct SlotManager {
    slots: VecDeque<Slot>,
    max_slots: usize,
}

impl SlotManager {
    pub fn new() -> Self {
        SlotManager {
            slots: VecDeque::new(),
            max_slots: 10, // Default maximum slots
        }
    }

    pub fn allocate_slot(
        &mut self,
        seller_id: String,
        duration: u64,
    ) -> Result<Slot, String> {
        if self.slots.len() >= self.max_slots {
            return Err("No available slots".to_string());
        }

        let now = SystemTime::now();
        let slot = Slot {
            seller_id: seller_id,
            start_time: now,
            end_time: now + Duration::from_secs(duration),
            price: 0, // Price logic to be implemented
        };

        self.slots.push_back(slot.clone());
        Ok(slot)
    }
}