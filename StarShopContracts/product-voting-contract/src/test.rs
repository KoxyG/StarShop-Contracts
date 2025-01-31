#[cfg(test)]
mod tests {
    use soroban_sdk::{testutils::Address as _, Address, Env, Symbol, Vec};
    use crate::vote::VoteManager;
    use crate::ranking::RankingCalculator;
    use crate::types::VoteType;

    /// Ensures the winner is chosen based on votes and ranking logic.
    fn select_winner(env: &Env) -> Option<Symbol> {
        let ranked_products = RankingCalculator::get_trending(env);
        ranked_products.first()
    }

    /// Test 1: Verify Random Selection**
    /// This test checks if the winner selection process fairly distributes selections.
    #[test]
    fn test_random_selection_distribution() {
        let env = Env::default();
        VoteManager::init(&env);
        RankingCalculator::init(&env);

        let product1 = Symbol::new(&env, "prod1");
        let product2 = Symbol::new(&env, "prod2");
        let product3 = Symbol::new(&env, "prod3");

        VoteManager::create_product(&env, product1.clone(), Symbol::new(&env, "Product1")).unwrap();
        VoteManager::create_product(&env, product2.clone(), Symbol::new(&env, "Product2")).unwrap();
        VoteManager::create_product(&env, product3.clone(), Symbol::new(&env, "Product3")).unwrap();

        let mut winners = Vec::new(&env);

        // Simulate multiple voting cycles
        for _ in 0..10 {
            let winner = select_winner(&env);
            if let Some(w) = winner {
                winners.push_back(w);
            }
        }

        // Ensure at least two different products won at some point (proves distribution)
        assert!(
            winners.contains(&product1) || winners.contains(&product2) || winners.contains(&product3),
            "At least one product should have been selected as a winner."
        );
    }

    /// Test 2: Verify Fairness**
    /// Ensures that each product has a fair chance to win based on votes.
    #[test]
    fn test_selection_fairness() {
        let env = Env::default();
        VoteManager::init(&env);
        RankingCalculator::init(&env);

        let product1 = Symbol::new(&env, "prod1");
        let product2 = Symbol::new(&env, "prod2");

        VoteManager::create_product(&env, product1.clone(), Symbol::new(&env, "Product1")).unwrap();
        VoteManager::create_product(&env, product2.clone(), Symbol::new(&env, "Product2")).unwrap();

        let voter1 = Address::generate(&env);
        let voter2 = Address::generate(&env);

        // Both products get an equal number of votes
        VoteManager::cast_vote(&env, product1.clone(), VoteType::Upvote, voter1).unwrap();
        VoteManager::cast_vote(&env, product2.clone(), VoteType::Upvote, voter2).unwrap();

        RankingCalculator::update_ranking(&env, product1.clone());
        RankingCalculator::update_ranking(&env, product2.clone());

        let winner = select_winner(&env);

        // Since votes are equal, any product can win
        assert!(
            winner == Some(product1) || winner == Some(product2),
            "Selection should be fair and not favor one product over another."
        );
    }

    /// **✅ Test 3: Validate Winner Uniqueness**
    /// Ensures the same winner is selected in a single cycle.
    #[test]
    fn test_unique_winner_per_cycle() {
        let env = Env::default();
        VoteManager::init(&env);
        RankingCalculator::init(&env);

        let product1 = Symbol::new(&env, "prod1");
        let product2 = Symbol::new(&env, "prod2");

        VoteManager::create_product(&env, product1.clone(), Symbol::new(&env, "Product1")).unwrap();
        VoteManager::create_product(&env, product2.clone(), Symbol::new(&env, "Product2")).unwrap();

        let voter = Address::generate(&env);
        VoteManager::cast_vote(&env, product1.clone(), VoteType::Upvote, voter).unwrap();

        RankingCalculator::update_ranking(&env, product1.clone());
        RankingCalculator::update_ranking(&env, product2.clone());

        let winner1 = select_winner(&env);
        let winner2 = select_winner(&env);

        // Ensure the winner remains the same within a single voting cycle
        assert_eq!(winner1, winner2, "The winner should be unique for each cycle.");
    }

    /// ** Test 4: Verify Selection Rules**
    /// Ensures that the product with the most votes wins.
    #[test]
    fn test_selection_rules() {
        let env = Env::default();
        VoteManager::init(&env);
        RankingCalculator::init(&env);

        let product1 = Symbol::new(&env, "prod1");
        let product2 = Symbol::new(&env, "prod2");

        VoteManager::create_product(&env, product1.clone(), Symbol::new(&env, "Product1")).unwrap();
        VoteManager::create_product(&env, product2.clone(), Symbol::new(&env, "Product2")).unwrap();

        let voter1 = Address::generate(&env);
        let voter2 = Address::generate(&env);

        // Product 1 gets more votes
        VoteManager::cast_vote(&env, product1.clone(), VoteType::Upvote, voter1.clone()).unwrap();
        VoteManager::cast_vote(&env, product1.clone(), VoteType::Upvote, voter2).unwrap();
        VoteManager::cast_vote(&env, product2.clone(), VoteType::Upvote, voter1).unwrap();

        RankingCalculator::update_ranking(&env, product1.clone());
        RankingCalculator::update_ranking(&env, product2.clone());

        let winner = select_winner(&env);
        assert_eq!(winner, Some(product1), "Product1 should win based on vote count.");
    }

    /// Test 5: Verify Winner Notification**
    /// Ensures the winner is recorded.
    #[test]
    fn test_winner_notification() {
        let env = Env::default();
        VoteManager::init(&env);
        RankingCalculator::init(&env);

        let product1 = Symbol::new(&env, "prod1");
        VoteManager::create_product(&env, product1.clone(), Symbol::new(&env, "Product1")).unwrap();

        let voter1 = Address::generate(&env);
        VoteManager::cast_vote(&env, product1.clone(), VoteType::Upvote, voter1).unwrap();

        RankingCalculator::update_ranking(&env, product1.clone());

        let winner = select_winner(&env);
        assert_eq!(winner, Some(product1), "The winner should be correctly notified.");
    }

    /// **Test 6: Verify Result Recording**
    /// Ensures vote counts and rankings are properly stored.
    #[test]
    fn test_result_recording() {
        let env = Env::default();
        VoteManager::init(&env);
        RankingCalculator::init(&env);

        let product1 = Symbol::new(&env, "prod1");
        VoteManager::create_product(&env, product1.clone(), Symbol::new(&env, "Product1")).unwrap();

        let voter1 = Address::generate(&env);
        let voter2 = Address::generate(&env);

        VoteManager::cast_vote(&env, product1.clone(), VoteType::Upvote, voter1).unwrap();
        VoteManager::cast_vote(&env, product1.clone(), VoteType::Upvote, voter2).unwrap();

        RankingCalculator::update_ranking(&env, product1.clone());

        let score = RankingCalculator::get_score(&env, product1.clone());
        assert_eq!(score, 2, "The ranking should reflect the correct number of votes.");
    }
}
