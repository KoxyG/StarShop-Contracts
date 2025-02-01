#[cfg(test)]
mod tests {

    use crate::types::VoteType;
    use crate::{ProductVoting, ProductVotingClient};
    use soroban_sdk::{
        testutils::Address as _,
        testutils::{Ledger, LedgerInfo},
        Address, Env, Symbol,
    };

    const DAILY_VOTE_LIMIT: u32 = 10;
    const MIN_ACCOUNT_AGE: u64 = 7 * 24 * 60 * 60; // 7 days in seconds

    #[test]
    fn test_create_product() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register(ProductVoting, ());
        let client = ProductVotingClient::new(&env, &contract_id);

        let id = Symbol::new(&env, "product1");
        let name = Symbol::new(&env, "Product_1");
        client.init();

        let result = client.try_create_product(&id, &name);
        assert!(result.is_ok(), "create_product failed with an error");
        let score = client.get_product_score(&id);
        assert_eq!(score, 0)
    }

    #[test]
    fn test_duplicate_product_creation() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register(ProductVoting, ());
        let client = ProductVotingClient::new(&env, &contract_id);

        let id = Symbol::new(&env, "product1");
        let name = Symbol::new(&env, "Product_1");

        // First creation should succeed
        client.create_product(&id, &name);

        // Second creation should fail with ProductExists
        let result = client.try_create_product(&id, &name);

        // Ensure the result is an error
        assert!(result.is_err(), "Expected error, but got Ok");
    }

    #[test]
    fn test_daily_vote_limit() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register(ProductVoting, ());
        let client = ProductVotingClient::new(&env, &contract_id);

        let id = Symbol::new(&env, "product1");
        let name = Symbol::new(&env, "Product_1");

        let voter = Address::generate(&env);

        client.init();

        env.ledger().set(LedgerInfo {
            timestamp: env.ledger().timestamp() + MIN_ACCOUNT_AGE,
            protocol_version: 22,
            sequence_number: 100,
            network_id: [0; 32],
            base_reserve: 10,
            min_temp_entry_ttl: 1000,
            min_persistent_entry_ttl: 1000,
            max_entry_ttl: 6312000,
            ..Default::default()
        });

        client.create_product(&id, &name);

        for _ in 0..DAILY_VOTE_LIMIT {
            let result = client.try_cast_vote(&id, &VoteType::Upvote, &voter);
            assert!(result.is_ok());
        }

        let result = client.try_cast_vote(&id, &VoteType::Upvote, &voter);

        assert!(result.is_err(), "Expected error, but got Ok");
    }

    #[test]
    fn test_account_too_new() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register(ProductVoting, ());
        let client = ProductVotingClient::new(&env, &contract_id);

        let id = Symbol::new(&env, "product1");
        let name = Symbol::new(&env, "Product_1");

        let voter = Address::generate(&env);

        client.init();

        client.create_product(&id, &name);
        let result = client.try_cast_vote(&id, &VoteType::Upvote, &voter);

        assert!(result.is_err(), "Expected error, but got Ok");
    }

    #[test]
    fn test_reversal_window_expired() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register(ProductVoting, ());
        let client = ProductVotingClient::new(&env, &contract_id);

        let id = Symbol::new(&env, "product1");
        let name = Symbol::new(&env, "Product_1");

        let voter = Address::generate(&env);

        client.init();

        env.ledger().set(LedgerInfo {
            timestamp: env.ledger().timestamp() + MIN_ACCOUNT_AGE,
            protocol_version: 22,
            sequence_number: 100,
            network_id: [0; 32],
            base_reserve: 10,
            min_temp_entry_ttl: 1000,
            min_persistent_entry_ttl: 1000,
            max_entry_ttl: 6312000,
            ..Default::default()
        });

        client.create_product(&id, &name);
        client.cast_vote(&id, &VoteType::Upvote, &voter);

        // Simulate time passing
        env.ledger().set(LedgerInfo {
            timestamp: env.ledger().timestamp() + 24 * 60 * 60 + 1,
            protocol_version: 22,
            sequence_number: 100,
            network_id: [0; 32],
            base_reserve: 10,
            min_temp_entry_ttl: 1000,
            min_persistent_entry_ttl: 1000,
            max_entry_ttl: 6312000,
            ..Default::default()
        });

        // Try casting a downvote after the reversal window has expired
        let result = client.try_cast_vote(&id, &VoteType::Downvote, &voter);

        // Assert the result is an error
        assert!(result.is_err(), "Expected error, but got Ok");
    }
}
