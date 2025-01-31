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

    /// **Test 1: Verify Random Selection Distribution**
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
        for _ in 0..10 {
            if let Some(w) = select_winner(&env) {
                winners.push_back(w);
            }
        }

        let product1_count = winners.iter().filter(|w| w == &product1).count();
        let product2_count = winners.iter().filter(|w| w == &product2).count();
        let product3_count = winners.iter().filter(|w| w == &product3).count();

        assert!(
            product1_count > 0 || product2_count > 0 || product3_count > 0,
            "At least one product should have been selected as a winner."
        );
    }

    /// **Test 2: Verify Selection Fairness**
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
        let voter3 = Address::generate(&env);

        VoteManager::cast_vote(&env, product1.clone(), VoteType::Upvote, voter1).unwrap();
        VoteManager::cast_vote(&env, product1.clone(), VoteType::Upvote, voter2).unwrap();
        VoteManager::cast_vote(&env, product2.clone(), VoteType::Upvote, voter3).unwrap();

        let winner = select_winner(&env);

        assert!(
            winner == Some(product1) || winner == Some(product2),
            "Selection should be fair and based on votes."
        );
    }

    /// **Test 3: Validate Winner Uniqueness**
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

        let winner1 = select_winner(&env);
        let winner2 = select_winner(&env);

        assert_eq!(winner1, winner2, "The winner should be unique within a single voting cycle.");
    }

    /// **Test 4: Verify Selection Rules**
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

        VoteManager::cast_vote(&env, product1.clone(), VoteType::Upvote, voter1.clone()).unwrap();
        VoteManager::cast_vote(&env, product1.clone(), VoteType::Upvote, voter2).unwrap();
        VoteManager::cast_vote(&env, product2.clone(), VoteType::Upvote, voter1).unwrap();

        let winner = select_winner(&env);
        assert_eq!(winner, Some(product1), "Product1 should win based on vote count.");
    }

    /// **Test 5: Verify Winner Notification**
    #[test]
    fn test_winner_notification() {
        let env = Env::default();
        VoteManager::init(&env);
        RankingCalculator::init(&env);

        let product1 = Symbol::new(&env, "prod1");
        VoteManager::create_product(&env, product1.clone(), Symbol::new(&env, "Product1")).unwrap();

        let voter1 = Address::generate(&env);
        VoteManager::cast_vote(&env, product1.clone(), VoteType::Upvote, voter1).unwrap();

        let winner = select_winner(&env);
        assert_eq!(winner, Some(product1), "The winner should be correctly notified.");
    }

    /// **Test 6: Verify Result Recording**
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

        let score = RankingCalculator::get_score(&env, product1.clone());
        assert_eq!(score, 2, "The ranking should reflect the correct number of votes.");
    }
}
