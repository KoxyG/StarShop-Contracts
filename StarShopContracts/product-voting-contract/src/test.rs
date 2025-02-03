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
    
    #[test]
    fn test_vote_result_accuracy() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register(ProductVoting, ());
        let client = ProductVotingClient::new(&env, &contract_id);

        let id = Symbol::new(&env, "test_product");
        let name = Symbol::new(&env, "Test_Product");
        client.init();
        client.create_product(&id, &name);

        // Set initial timestamp
        let initial_time = 1000000;
        env.ledger().set(LedgerInfo {
            timestamp: initial_time + 8 * 24 * 60 * 60, // Setting valid account age
            protocol_version: 22,
            sequence_number: 100,
            network_id: [0; 32],
            base_reserve: 10,
            min_temp_entry_ttl: 1000,
            min_persistent_entry_ttl: 1000,
            max_entry_ttl: 6312000,
            ..Default::default()
        });

        // Generate test voters
        let voters = [
            Address::generate(&env),
            Address::generate(&env),
            Address::generate(&env),
        ];

        // Cast votes: 2 upvotes, 1 downvote
        client.cast_vote(&id, &VoteType::Upvote, &voters[0]);
        client.cast_vote(&id, &VoteType::Upvote, &voters[1]);
        client.cast_vote(&id, &VoteType::Downvote, &voters[2]);

        // The score should be 1 because:
        // - Base score = 2 upvotes - 1 downvote = 1
        // - No time decay yet as all votes are recent
        // - Recent votes bonus = 3 votes / 2 = 1
        // Total score should be 1
        let score = client.get_product_score(&id);
        assert_eq!(score, 1, "Vote calculation should be accurate");
    }

    #[test]
    fn test_trending_products_verification() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register(ProductVoting, ());
        let client = ProductVotingClient::new(&env, &contract_id);
        client.init();

        // Create test products
        let product1 = Symbol::new(&env, "product1");
        let product2 = Symbol::new(&env, "product2");
        client.create_product(&product1, &Symbol::new(&env, "Product_1"));
        client.create_product(&product2, &Symbol::new(&env, "Product_2"));

        // Set valid account age
        env.ledger().set(LedgerInfo {
            timestamp: env.ledger().timestamp() + 8 * 24 * 60 * 60,
            protocol_version: 22,
            sequence_number: 100,
            network_id: [0; 32],
            base_reserve: 10,
            min_temp_entry_ttl: 1000,
            min_persistent_entry_ttl: 1000,
            max_entry_ttl: 6312000,
            ..Default::default()
        });

        // Generate voters
        let voter1 = Address::generate(&env);
        let voter2 = Address::generate(&env);

        // Product 1 gets more votes
        client.cast_vote(&product1, &VoteType::Upvote, &voter1);
        client.cast_vote(&product1, &VoteType::Upvote, &voter2);

        // Product 2 gets fewer votes
        client.cast_vote(&product2, &VoteType::Upvote, &voter1);

        let trending = client.get_trending_products();
        assert_eq!(
            trending.get(0).unwrap(),
            product1,
            "Most voted product should be first"
        );
        assert_eq!(
            trending.get(1).unwrap(),
            product2,
            "Less voted product should be second"
        );
    }

    #[test]
    fn test_vote_reversal_transparency() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register(ProductVoting, ());
        let client = ProductVotingClient::new(&env, &contract_id);

        let id = Symbol::new(&env, "test_product");
        let name = Symbol::new(&env, "Test_Product");
        client.init();
        client.create_product(&id, &name);

        let voter = Address::generate(&env);

        // Set valid account age
        env.ledger().set(LedgerInfo {
            timestamp: env.ledger().timestamp() + 8 * 24 * 60 * 60,
            protocol_version: 22,
            sequence_number: 100,
            network_id: [0; 32],
            base_reserve: 10,
            min_temp_entry_ttl: 1000,
            min_persistent_entry_ttl: 1000,
            max_entry_ttl: 6312000,
            ..Default::default()
        });

        // Initial upvote
        client.cast_vote(&id, &VoteType::Upvote, &voter);

        client.cast_vote(&id, &VoteType::Downvote, &voter);

        let final_score = client.get_product_score(&id);
        assert_eq!(
            final_score, 0,
            "Vote reversal should be transparent and accurate"
        )
    }

    #[test]
    fn test_multiple_vote_validation() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register(ProductVoting, ());
        let client = ProductVotingClient::new(&env, &contract_id);

        let id = Symbol::new(&env, "test_product");
        let name = Symbol::new(&env, "Test_Product");
        client.init();
        client.create_product(&id, &name);

        let voter = Address::generate(&env);

        // Set initial timestamp for valid account age
        env.ledger().set(LedgerInfo {
            timestamp: env.ledger().timestamp() + 8 * 24 * 60 * 60,
            protocol_version: 22,
            sequence_number: 100,
            network_id: [0; 32],
            base_reserve: 10,
            min_temp_entry_ttl: 1000,
            min_persistent_entry_ttl: 1000,
            max_entry_ttl: 6312000,
            ..Default::default()
        });

        // Initial vote
        client.cast_vote(&id, &VoteType::Upvote, &voter);

        env.ledger().set(LedgerInfo {
            timestamp: env.ledger().timestamp() + 25 * 60 * 60,
            protocol_version: 22,
            sequence_number: 100,
            network_id: [0; 32],
            base_reserve: 10,
            min_temp_entry_ttl: 1000,
            min_persistent_entry_ttl: 1000,
            max_entry_ttl: 6312000,
            ..Default::default()
        });

        // Attempt duplicate vote should fail
        let result = client.try_cast_vote(&id, &VoteType::Upvote, &voter);
        assert!(
            result.is_err(),
            "Should prevent multiple votes after reversal window"
        );
    }
}
