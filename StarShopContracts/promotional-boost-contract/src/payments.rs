use soroban_sdk::{token, Address, Env};

pub struct PaymentProcessor;

impl PaymentProcessor {
    /// Accepts a payment in XLM from the seller and verifies it's at least the required amount
    pub fn collect_payment(
        env: &Env,
        from: &Address,
        amount: i128,
        price_required: i128,
    ) -> Result<(), &'static str> {
        if amount < price_required {
            return Err("Insufficient payment");
        }

        let token_id = Address::from_str(
            &env,
            "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC",
        );
        let token = token::Client::new(&env, &token_id);
        token.transfer(from, &env.current_contract_address(), &amount);

        Ok(())
    }

    /// Refund a payment in XLM to the given address
    pub fn refund_payment(env: &Env, to: &Address, amount: i128) -> Result<(), &'static str> {
        if amount <= 0 {
            return Err("Nothing to refund");
        }

        let token_id = Address::from_str(
            &env,
            "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC",
        );
        let token = token::Client::new(&env, &token_id);
        token.transfer(&env.current_contract_address(), to, &amount);

        Ok(())
    }

    /// Calculates required slot price (fixed-tier example, but can be replaced with auction logic)
    pub fn calculate_price(duration_secs: u64) -> i128 {
        let base_price = 5_000_000i128; // 5 XLM in stroops (1 XLM = 1_000_000 stroops)
        let daily_rate = base_price; // per day rate

        let days = (duration_secs as f64 / 86400.0).ceil() as i128;
        days * daily_rate
    }
}
