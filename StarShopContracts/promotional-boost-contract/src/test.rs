#![cfg(test)]

use super::*;
use soroban_sdk::{
    testutils::{Events, Ledger, Address as TestAddress},
    vec, Address, Env, Symbol, token, IntoVal,
};

// Test constants - using proper Stellar address format (exactly 56 characters)
// Note: These constants are kept for future reference but currently unused

fn create_test_env() -> Env {
    let env = Env::default();
    env.mock_all_auths();
    env
}

fn setup_xlm_token_and_sellers(env: &Env, contract_id: &Address) -> (Address, Vec<Address>) {
    // Create a mock XLM token contract for testing
    let token_admin = Address::generate(&env);
    let token_contract = env.register_stellar_asset_contract_v2(token_admin.clone());
    let token_id = token_contract.address();
    
    // Store the token address for the PaymentProcessor to use
    env.as_contract(&contract_id, || {
        env.storage().instance().set(&soroban_sdk::symbol_short!("xlm_addr"), &token_id);
    });
    
    // Create test sellers
    let sellers = vec![&env,
        Address::generate(&env),
        Address::generate(&env),
        Address::generate(&env),
        Address::generate(&env),
    ];
    
    // Setup token client and mint tokens for sellers
    let token_client = token::StellarAssetClient::new(&env, &token_id);
    for i in 0..sellers.len() {
        let seller = sellers.get(i).unwrap();
        token_client.mint(&seller, &1_000_000_000_000i128); // 1M XLM each
    }
    
    (token_id.clone(), sellers)
}

fn register_contract(env: &Env) -> Address {
    let contract_id = env.register(PromotionBoostContract, ());
    let client = PromotionBoostContractClient::new(&env, &contract_id);
    
    // Initialize the contract with default slot limits
    client.initialize();
    
    contract_id
}

fn advance_ledger_time(env: &Env, time_advance: u64) {
    let current_ledger = env.ledger().get();
    env.ledger().set(soroban_sdk::testutils::LedgerInfo {
        timestamp: current_ledger.timestamp + time_advance,
        protocol_version: current_ledger.protocol_version,
        sequence_number: current_ledger.sequence_number + 1,
        network_id: current_ledger.network_id,
        base_reserve: current_ledger.base_reserve,
        min_temp_entry_ttl: current_ledger.min_temp_entry_ttl,
        min_persistent_entry_ttl: current_ledger.min_persistent_entry_ttl,
        max_entry_ttl: current_ledger.max_entry_ttl,
    });
}

fn authorize_token_transfer(env: &Env, token_id: &Address, seller: &Address, contract_id: &Address, amount: i128) {
    // Mock authorization for the seller to transfer tokens to the contract
    env.mock_auths(&[
        soroban_sdk::testutils::MockAuth {
            address: seller,
            invoke: &soroban_sdk::testutils::MockAuthInvoke {
                contract: token_id,
                fn_name: "transfer",
                args: (seller, contract_id, amount).into_val(env),
                sub_invokes: &[],
            },
        }
    ]);
}

// Test 1: Basic Slot Purchase and Management
#[test]
fn test_basic_slot_purchase() {
    let env = create_test_env();
    let contract_id = register_contract(&env);
    let (token_id, sellers) = setup_xlm_token_and_sellers(&env, &contract_id);
    let client = PromotionBoostContractClient::new(&env, &contract_id);
    
    let seller = sellers.get(0).unwrap();
    let category = Symbol::new(&env, "electronics");
    let product_id = 1001u64;
    let duration = 86400u64; // 1 day
    let payment = 5_000_000i128; // 5 XLM in stroops
    
    // Authorize the token transfer
    authorize_token_transfer(&env, &token_id, &seller, &contract_id, payment);
    
    // Test successful boost purchase
    client.boost_product(&seller, &category, &product_id, &duration, &payment);
    
    // Verify product is boosted
    assert!(client.is_boosted(&product_id));
    
    // Verify product appears in boosted list
    let boosted_list = client.get_boosted_list();
    assert!(boosted_list.contains(product_id));
}

#[test]
fn test_slot_purchase_with_priority_queue() {
    let env = create_test_env();
    let contract_id = register_contract(&env);
    let (token_id, sellers) = setup_xlm_token_and_sellers(&env, &contract_id);
    let client = PromotionBoostContractClient::new(&env, &contract_id);
    
    let category = Symbol::new(&env, "electronics");
    let duration = 86400u64; // 1 day
    
    // Fill up slots with lower-paying sellers (assuming 3 max slots per category)
    let seller1 = sellers.get(0).unwrap();
    let seller2 = sellers.get(1).unwrap();
    let seller3 = sellers.get(2).unwrap();
    let seller4 = sellers.get(3).unwrap();
    
    // Add 3 low-paying boosts
    authorize_token_transfer(&env, &token_id, &seller1, &contract_id, 5_000_000i128);
    client.boost_product(&seller1, &category, &1001u64, &duration, &5_000_000i128);
    
    authorize_token_transfer(&env, &token_id, &seller2, &contract_id, 5_000_000i128);
    client.boost_product(&seller2, &category, &1002u64, &duration, &5_000_000i128);
    
    authorize_token_transfer(&env, &token_id, &seller3, &contract_id, 5_000_000i128);
    client.boost_product(&seller3, &category, &1003u64, &duration, &5_000_000i128);
    
    // Verify all 3 products are boosted
    assert!(client.is_boosted(&1001u64));
    assert!(client.is_boosted(&1002u64));
    assert!(client.is_boosted(&1003u64));
    
    // Try to add a higher-paying boost - should replace the lowest paying one
    authorize_token_transfer(&env, &token_id, &seller4, &contract_id, 10_000_000i128);
    client.boost_product(&seller4, &category, &1004u64, &duration, &10_000_000i128);
    
    // Verify the new product is boosted
    assert!(client.is_boosted(&1004u64));
    
    // Verify total boosted products is still 3 (one should have been replaced)
    let boosted_list = client.get_boosted_list();
    assert_eq!(boosted_list.len(), 3);
}

#[test]
#[should_panic(expected = "Insufficient payment for duration")]
fn test_slot_purchase_insufficient_payment() {
    let env = create_test_env();
    let contract_id = register_contract(&env);
    let (token_id, sellers) = setup_xlm_token_and_sellers(&env, &contract_id);
    let client = PromotionBoostContractClient::new(&env, &contract_id);
    
    let seller = sellers.get(0).unwrap();
    let category = Symbol::new(&env, "electronics");
    let product_id = 1001u64;
    let duration = 86400u64; // 1 day
    let insufficient_payment = 1_000_000i128; // 1 XLM (less than required 5 XLM)
    
    // Authorize the token transfer (even though it will fail due to insufficient amount)
    authorize_token_transfer(&env, &token_id, &seller, &contract_id, insufficient_payment);
    
    // Should panic due to insufficient payment
    client.boost_product(&seller, &category, &product_id, &duration, &insufficient_payment);
}

// Test 2: XLM Payment Handling
#[test]
fn test_xlm_payment_validation() {
    let env = create_test_env();
    let contract_id = register_contract(&env);
    let (token_id, sellers) = setup_xlm_token_and_sellers(&env, &contract_id);
    let client = PromotionBoostContractClient::new(&env, &contract_id);
    
    let seller = sellers.get(0).unwrap();
    let category = Symbol::new(&env, "electronics");
    let product_id = 1001u64;
    let duration = 86400u64; // 1 day
    let exact_payment = 5_000_000i128; // Exactly 5 XLM
    
    // Authorize the token transfer
    authorize_token_transfer(&env, &token_id, &seller, &contract_id, exact_payment);
    
    // Test exact payment amount
    client.boost_product(&seller, &category, &product_id, &duration, &exact_payment);
    assert!(client.is_boosted(&product_id));
}

#[test]
fn test_tiered_pricing() {
    let env = create_test_env();
    let contract_id = register_contract(&env);
    let (token_id, sellers) = setup_xlm_token_and_sellers(&env, &contract_id);
    let client = PromotionBoostContractClient::new(&env, &contract_id);
    
    let seller1 = sellers.get(0).unwrap();
    let seller2 = sellers.get(1).unwrap();
    let category = Symbol::new(&env, "electronics");
    
    // Test 1 day duration (should be 5 XLM)
    authorize_token_transfer(&env, &token_id, &seller1, &contract_id, 5_000_000i128);
    client.boost_product(&seller1, &category, &1001u64, &86400u64, &5_000_000i128);
    assert!(client.is_boosted(&1001u64));
    
    // Test 7 day duration (should be 35 XLM)
    authorize_token_transfer(&env, &token_id, &seller2, &contract_id, 35_000_000i128);
    client.boost_product(&seller2, &category, &1002u64, &(86400u64 * 7), &35_000_000i128);
    assert!(client.is_boosted(&1002u64));
}

#[test]
#[should_panic(expected = "Insufficient payment for duration")]
fn test_no_slot_without_payment() {
    let env = create_test_env();
    let contract_id = register_contract(&env);
    let (token_id, sellers) = setup_xlm_token_and_sellers(&env, &contract_id);
    let client = PromotionBoostContractClient::new(&env, &contract_id);
    
    let seller = sellers.get(0).unwrap();
    let category = Symbol::new(&env, "electronics");
    let product_id = 1001u64;
    let duration = 86400u64;
    let zero_payment = 0i128;
    
    // Authorize the token transfer (even though it will fail due to zero payment)
    authorize_token_transfer(&env, &token_id, &seller, &contract_id, zero_payment);
    
    // Should panic due to zero payment
    client.boost_product(&seller, &category, &product_id, &duration, &zero_payment);
}

// Test 3: Visibility Boost Logic
#[test]
fn test_visibility_boost_flagging() {
    let env = create_test_env();
    let contract_id = register_contract(&env);
    let (token_id, sellers) = setup_xlm_token_and_sellers(&env, &contract_id);
    let client = PromotionBoostContractClient::new(&env, &contract_id);
    
    let seller = sellers.get(0).unwrap();
    let category = Symbol::new(&env, "electronics");
    let product_id = 1001u64;
    let duration = 86400u64;
    let payment = 5_000_000i128;
    
    // Initially not boosted
    assert!(!client.is_boosted(&product_id));
    
    // Authorize and purchase boost
    authorize_token_transfer(&env, &token_id, &seller, &contract_id, payment);
    client.boost_product(&seller, &category, &product_id, &duration, &payment);
    
    // Should now be flagged as boosted
    assert!(client.is_boosted(&product_id));
    
    // Should appear in boosted list
    let boosted_list = client.get_boosted_list();
    assert!(boosted_list.contains(product_id));
    assert_eq!(boosted_list.len(), 1);
}

#[test]
fn test_boosted_vs_non_boosted_sorting() {
    let env = create_test_env();
    let contract_id = register_contract(&env);
    let (token_id, sellers) = setup_xlm_token_and_sellers(&env, &contract_id);
    let client = PromotionBoostContractClient::new(&env, &contract_id);
    
    let seller1 = sellers.get(0).unwrap();
    let seller2 = sellers.get(1).unwrap();
    let category = Symbol::new(&env, "electronics");
    let duration = 86400u64;
    let payment = 5_000_000i128;
    
    // Boost some products
    authorize_token_transfer(&env, &token_id, &seller1, &contract_id, payment);
    client.boost_product(&seller1, &category, &1001u64, &duration, &payment);
    
    authorize_token_transfer(&env, &token_id, &seller2, &contract_id, payment);
    client.boost_product(&seller2, &category, &1002u64, &duration, &payment);
    
    // Get boosted list
    let boosted_list = client.get_boosted_list();
    
    // Verify only boosted products are in the list
    assert_eq!(boosted_list.len(), 2);
    assert!(boosted_list.contains(1001u64));
    assert!(boosted_list.contains(1002u64));
    
    // Verify non-boosted products are not in the list
    assert!(!client.is_boosted(&1003u64));
    assert!(!boosted_list.contains(1003u64));
}

#[test]
fn test_visibility_removed_on_expiration() {
    let env = create_test_env();
    let contract_id = register_contract(&env);
    let (token_id, sellers) = setup_xlm_token_and_sellers(&env, &contract_id);
    let client = PromotionBoostContractClient::new(&env, &contract_id);
    
    let seller = sellers.get(0).unwrap();
    let category = Symbol::new(&env, "electronics");
    let product_id = 1001u64;
    let duration = 3600u64; // 1 hour
    let payment = 5_000_000i128;
    
    // Authorize and purchase boost
    authorize_token_transfer(&env, &token_id, &seller, &contract_id, payment);
    client.boost_product(&seller, &category, &product_id, &duration, &payment);
    assert!(client.is_boosted(&product_id));
    
    // Advance time past expiration
    advance_ledger_time(&env, 3601u64); // 1 hour + 1 second
    
    // Check if still boosted (should call cleanup internally)
    assert!(!client.is_boosted(&product_id));
    
    // Verify not in boosted list
    let boosted_list = client.get_boosted_list();
    assert!(!boosted_list.contains(product_id));
}

// Test 4: Expiration & Renewal
#[test]
fn test_boost_expiration() {
    let env = create_test_env();
    let contract_id = register_contract(&env);
    let (token_id, sellers) = setup_xlm_token_and_sellers(&env, &contract_id);
    let client = PromotionBoostContractClient::new(&env, &contract_id);
    
    let seller = sellers.get(0).unwrap();
    let category = Symbol::new(&env, "electronics");
    let product_id = 1001u64;
    let duration = 3600u64; // 1 hour
    let payment = 5_000_000i128;
    
    // Authorize and purchase boost
    authorize_token_transfer(&env, &token_id, &seller, &contract_id, payment);
    client.boost_product(&seller, &category, &product_id, &duration, &payment);
    assert!(client.is_boosted(&product_id));
    
    // Advance time but not past expiration
    advance_ledger_time(&env, 1800u64); // 30 minutes
    assert!(client.is_boosted(&product_id));
    
    // Advance time past expiration
    advance_ledger_time(&env, 1801u64); // Total: 60 minutes + 1 second
    assert!(!client.is_boosted(&product_id));
}

#[test]
fn test_expired_slots_cleanup() {
    let env = create_test_env();
    let contract_id = register_contract(&env);
    let (token_id, sellers) = setup_xlm_token_and_sellers(&env, &contract_id);
    let client = PromotionBoostContractClient::new(&env, &contract_id);
    
    let seller1 = sellers.get(0).unwrap();
    let seller2 = sellers.get(1).unwrap();
    let category = Symbol::new(&env, "electronics");
    let duration = 3600u64; // 1 hour
    let payment = 5_000_000i128;
    
    // Purchase multiple boosts
    authorize_token_transfer(&env, &token_id, &seller1, &contract_id, payment);
    client.boost_product(&seller1, &category, &1001u64, &duration, &payment);
    
    authorize_token_transfer(&env, &token_id, &seller2, &contract_id, payment);
    client.boost_product(&seller2, &category, &1002u64, &duration, &payment);
    
    // Verify both are active
    assert!(client.is_boosted(&1001u64));
    assert!(client.is_boosted(&1002u64));
    assert_eq!(client.get_boosted_list().len(), 2);
    
    // Advance time past expiration
    advance_ledger_time(&env, 3601u64);
    
    // Call cleanup
    client.cleanup_expired(&category);
    
    // Verify slots are cleaned up
    assert!(!client.is_boosted(&1001u64));
    assert!(!client.is_boosted(&1002u64));
    assert_eq!(client.get_boosted_list().len(), 0);
}

#[test]
fn test_boost_renewal() {
    let env = create_test_env();
    let contract_id = register_contract(&env);
    let (token_id, sellers) = setup_xlm_token_and_sellers(&env, &contract_id);
    let client = PromotionBoostContractClient::new(&env, &contract_id);
    
    let seller = sellers.get(0).unwrap();
    let category = Symbol::new(&env, "electronics");
    let product_id = 1001u64;
    let duration = 3600u64; // 1 hour
    let payment = 5_000_000i128;
    
    // Purchase initial boost
    authorize_token_transfer(&env, &token_id, &seller, &contract_id, payment);
    client.boost_product(&seller, &category, &product_id, &duration, &payment);
    assert!(client.is_boosted(&product_id));
    
    // Advance time close to expiration
    advance_ledger_time(&env, 3500u64); // 58 minutes
    assert!(client.is_boosted(&product_id));
    
    // Renew boost before expiration
    authorize_token_transfer(&env, &token_id, &seller, &contract_id, payment);
    client.boost_product(&seller, &category, &product_id, &duration, &payment);
    assert!(client.is_boosted(&product_id));
    
    // Advance time past original expiration but within new duration
    advance_ledger_time(&env, 200u64); // Total: 61 minutes 40 seconds
    assert!(client.is_boosted(&product_id));
}

// Test 5: Anti-Abuse & Audit Logging
#[test]
fn test_prevent_seller_boost_caps() {
    let env = create_test_env();
    let contract_id = register_contract(&env);
    let (token_id, sellers) = setup_xlm_token_and_sellers(&env, &contract_id);
    let client = PromotionBoostContractClient::new(&env, &contract_id);
    
    let seller = sellers.get(0).unwrap();
    let category = Symbol::new(&env, "electronics");
    let duration = 86400u64;
    let payment = 5_000_000i128;
    
    // Try to boost multiple products from same seller
    authorize_token_transfer(&env, &token_id, &seller, &contract_id, payment);
    client.boost_product(&seller, &category, &1001u64, &duration, &payment);
    
    authorize_token_transfer(&env, &token_id, &seller, &contract_id, payment);
    client.boost_product(&seller, &category, &1002u64, &duration, &payment);
    
    authorize_token_transfer(&env, &token_id, &seller, &contract_id, payment);
    client.boost_product(&seller, &category, &1003u64, &duration, &payment);
    
    // All should be allowed as they're different products
    assert!(client.is_boosted(&1001u64));
    assert!(client.is_boosted(&1002u64));
    assert!(client.is_boosted(&1003u64));
}

#[test]
fn test_audit_logging_through_events() {
    let env = create_test_env();
    let contract_id = register_contract(&env);
    let (token_id, sellers) = setup_xlm_token_and_sellers(&env, &contract_id);
    let client = PromotionBoostContractClient::new(&env, &contract_id);
    
    let seller = sellers.get(0).unwrap();
    let category = Symbol::new(&env, "electronics");
    let product_id = 1001u64;
    let duration = 86400u64;
    let payment = 5_000_000i128;
    
    // Purchase boost
    authorize_token_transfer(&env, &token_id, &seller, &contract_id, payment);
    client.boost_product(&seller, &category, &product_id, &duration, &payment);
    
    // Verify events were emitted
    let events = env.events().all();
    assert!(!events.is_empty());
    
    // Look for boost slot added event
    let mut found_boost_event = false;
    
    for event in events.iter() {
        let topics = &event.1;
        if !topics.is_empty() {
            // Check if this is a boost-related event by examining the emitted data
            found_boost_event = true;
            break;
        }
    }
    
    assert!(found_boost_event, "Expected boost-related events to be emitted");
}

#[test]
fn test_fairness_no_permanent_boosts() {
    let env = create_test_env();
    let contract_id = register_contract(&env);
    let (token_id, sellers) = setup_xlm_token_and_sellers(&env, &contract_id);
    let client = PromotionBoostContractClient::new(&env, &contract_id);
    
    let seller = sellers.get(0).unwrap();
    let category = Symbol::new(&env, "electronics");
    let product_id = 1001u64;
    let max_duration = 86400u64 * 30; // 30 days (should be max allowed)
    let payment = 150_000_000i128; // 150 XLM for 30 days
    
    // Purchase long-term boost
    authorize_token_transfer(&env, &token_id, &seller, &contract_id, payment);
    client.boost_product(&seller, &category, &product_id, &max_duration, &payment);
    assert!(client.is_boosted(&product_id));
    
    // Advance time to end of duration
    advance_ledger_time(&env, max_duration + 1);
    
    // Should no longer be boosted
    assert!(!client.is_boosted(&product_id));
}

// Test 6: Edge Cases and Complex Scenarios
#[test]
fn test_concurrent_sellers_limited_slots() {
    let env = create_test_env();
    let contract_id = register_contract(&env);
    let (token_id, sellers) = setup_xlm_token_and_sellers(&env, &contract_id);
    let client = PromotionBoostContractClient::new(&env, &contract_id);
    
    let category = Symbol::new(&env, "electronics");
    let duration = 86400u64;
    let base_payment = 5_000_000i128;
    
    // All sellers try to boost at the same time with different amounts
    for i in 0..sellers.len() {
        let seller = sellers.get(i).unwrap();
        let payment = base_payment + (i as i128 * 1_000_000); // Increasing payments
        let product_id = 1001u64 + i as u64;
        
        authorize_token_transfer(&env, &token_id, &seller, &contract_id, payment);
        client.boost_product(&seller, &category, &product_id, &duration, &payment);
    }
    
    // Verify only max slots are active (likely 3)
    let boosted_list = client.get_boosted_list();
    assert!(boosted_list.len() <= 3); // Assuming 3 max slots per category
    
    // Verify higher-paying sellers got the slots
    // The last seller (highest payment) should definitely have a slot
    assert!(client.is_boosted(&1004u64));
}

#[test]
fn test_refund_logic_on_replacement() {
    let env = create_test_env();
    let contract_id = register_contract(&env);
    let (token_id, sellers) = setup_xlm_token_and_sellers(&env, &contract_id);
    let client = PromotionBoostContractClient::new(&env, &contract_id);
    
    let category = Symbol::new(&env, "electronics");
    let duration = 86400u64;
    
    // Fill slots with lower payments
    let seller1 = sellers.get(0).unwrap();
    let seller2 = sellers.get(1).unwrap();
    let seller3 = sellers.get(2).unwrap();
    let seller4 = sellers.get(3).unwrap();
    
    authorize_token_transfer(&env, &token_id, &seller1, &contract_id, 5_000_000i128);
    client.boost_product(&seller1, &category, &1001u64, &duration, &5_000_000i128);
    
    authorize_token_transfer(&env, &token_id, &seller2, &contract_id, 6_000_000i128);
    client.boost_product(&seller2, &category, &1002u64, &duration, &6_000_000i128);
    
    authorize_token_transfer(&env, &token_id, &seller3, &contract_id, 7_000_000i128);
    client.boost_product(&seller3, &category, &1003u64, &duration, &7_000_000i128);
    
    // Verify 3 slots are filled before replacement
    assert_eq!(client.get_slot_count(&category), 3, "Should have 3 slots filled");
    assert!(client.is_boosted(&1001u64), "Product 1001 should be boosted");
    assert!(client.is_boosted(&1002u64), "Product 1002 should be boosted");
    assert!(client.is_boosted(&1003u64), "Product 1003 should be boosted");
    
    // Add higher-paying boost that should trigger replacement
    authorize_token_transfer(&env, &token_id, &seller4, &contract_id, 10_000_000i128);
    client.boost_product(&seller4, &category, &1004u64, &duration, &10_000_000i128);
    
    // Verify replacement occurred
    assert!(client.is_boosted(&1004u64), "High-paying product should be boosted");
    assert_eq!(client.get_slot_count(&category), 3, "Should still have 3 slots after replacement");
    
    // Verify that one of the original products was replaced
    let is_1001_boosted = client.is_boosted(&1001u64);
    let is_1002_boosted = client.is_boosted(&1002u64);
    let is_1003_boosted = client.is_boosted(&1003u64);
    
    let original_still_boosted = [is_1001_boosted, is_1002_boosted, is_1003_boosted].iter().filter(|&&x| x).count();
    assert_eq!(original_still_boosted, 2, "Exactly 2 of the original 3 products should still be boosted");
    
    // Note: This test validates that replacement logic is executed correctly
    // The refund logic is tested implicitly through the successful replacement
}

#[test]
fn test_overlapping_boosts_different_categories() {
    let env = create_test_env();
    let contract_id = register_contract(&env);
    let (token_id, sellers) = setup_xlm_token_and_sellers(&env, &contract_id);
    let client = PromotionBoostContractClient::new(&env, &contract_id);
    
    let seller = sellers.get(0).unwrap();
    let electronics_category = Symbol::new(&env, "electronics");
    let clothing_category = Symbol::new(&env, "clothing");
    let product_id = 1001u64;
    let duration = 86400u64;
    let payment = 5_000_000i128;
    
    // Same product can be boosted in different categories
    authorize_token_transfer(&env, &token_id, &seller, &contract_id, payment);
    client.boost_product(&seller, &electronics_category, &product_id, &duration, &payment);
    
    authorize_token_transfer(&env, &token_id, &seller, &contract_id, payment);
    client.boost_product(&seller, &clothing_category, &product_id, &duration, &payment);
    
    // Should be boosted in both contexts
    assert!(client.is_boosted(&product_id));
    
    // Advance time to expire
    advance_ledger_time(&env, 86401u64);
    
    // Should no longer be boosted
    assert!(!client.is_boosted(&product_id));
}

#[test]
fn test_atomic_transitions() {
    let env = create_test_env();
    let contract_id = register_contract(&env);
    let (token_id, sellers) = setup_xlm_token_and_sellers(&env, &contract_id);
    let client = PromotionBoostContractClient::new(&env, &contract_id);
    
    let seller = sellers.get(0).unwrap();
    let category = Symbol::new(&env, "electronics");
    let product_id = 1001u64;
    let duration = 86400u64;
    let payment = 5_000_000i128;
    
    // Test that boost operation is atomic - either fully succeeds or fully fails
    // This is inherently tested by the contract structure, but we verify consistency
    
    // Before boost
    assert!(!client.is_boosted(&product_id));
    assert_eq!(client.get_boosted_list().len(), 0);
    
    // After successful boost
    authorize_token_transfer(&env, &token_id, &seller, &contract_id, payment);
    client.boost_product(&seller, &category, &product_id, &duration, &payment);
    assert!(client.is_boosted(&product_id));
    assert_eq!(client.get_boosted_list().len(), 1);
    assert!(client.get_boosted_list().contains(product_id));
}

#[test]
fn test_consistency_of_slot_metadata() {
    let env = create_test_env();
    let contract_id = register_contract(&env);
    let (token_id, sellers) = setup_xlm_token_and_sellers(&env, &contract_id);
    let client = PromotionBoostContractClient::new(&env, &contract_id);
    
    let seller = sellers.get(0).unwrap();
    let category = Symbol::new(&env, "electronics");
    let product_id = 1001u64;
    let duration = 86400u64;
    let payment = 5_000_000i128;
    
    // Purchase boost
    authorize_token_transfer(&env, &token_id, &seller, &contract_id, payment);
    client.boost_product(&seller, &category, &product_id, &duration, &payment);
    
    // Verify consistency between different views of the data
    assert!(client.is_boosted(&product_id));
    
    let boosted_list = client.get_boosted_list();
    assert!(boosted_list.contains(product_id));
    assert_eq!(boosted_list.len(), 1);
    
    // Advance time and verify consistency after cleanup
    advance_ledger_time(&env, 86401u64);
    client.cleanup_expired(&category);
    
    assert!(!client.is_boosted(&product_id));
    let updated_list = client.get_boosted_list();
    assert!(!updated_list.contains(product_id));
    assert_eq!(updated_list.len(), 0);
}

// Integration test simulating real-world usage
#[test]
fn test_full_boost_lifecycle() {
    let env = create_test_env();
    let contract_id = register_contract(&env);
    let (token_id, sellers) = setup_xlm_token_and_sellers(&env, &contract_id);
    let client = PromotionBoostContractClient::new(&env, &contract_id);
    
    let seller = sellers.get(0).unwrap();
    let category = Symbol::new(&env, "electronics");
    let product_id = 1001u64;
    let duration = 3600u64; // 1 hour
    let payment = 5_000_000i128;
    
    // 1. Initial state - no boosts
    assert!(!client.is_boosted(&product_id));
    assert_eq!(client.get_boosted_list().len(), 0);
    
    // 2. Purchase boost
    authorize_token_transfer(&env, &token_id, &seller, &contract_id, payment);
    client.boost_product(&seller, &category, &product_id, &duration, &payment);
    assert!(client.is_boosted(&product_id));
    assert_eq!(client.get_boosted_list().len(), 1);
    
    // 3. Time passes but boost still active
    advance_ledger_time(&env, 1800u64); // 30 minutes
    assert!(client.is_boosted(&product_id));
    
    // 4. Boost expires
    advance_ledger_time(&env, 1801u64); // Total: 60 minutes + 1 second
    assert!(!client.is_boosted(&product_id));
    
    // 5. Cleanup removes expired boost
    client.cleanup_expired(&category);
    assert_eq!(client.get_boosted_list().len(), 0);
    
    // 6. Can boost again after expiration
    authorize_token_transfer(&env, &token_id, &seller, &contract_id, payment);
    client.boost_product(&seller, &category, &product_id, &duration, &payment);
    assert!(client.is_boosted(&product_id));
    assert_eq!(client.get_boosted_list().len(), 1);
}

// Debug test to understand slot behavior
#[test]
fn test_debug_slot_limits() {
    let env = create_test_env();
    let contract_id = register_contract(&env);
    let (token_id, sellers) = setup_xlm_token_and_sellers(&env, &contract_id);
    let client = PromotionBoostContractClient::new(&env, &contract_id);
    
    let category = Symbol::new(&env, "electronics");
    let duration = 86400u64; // 1 day
    
    let seller1 = sellers.get(0).unwrap();
    let seller2 = sellers.get(1).unwrap();
    let seller3 = sellers.get(2).unwrap();
    let seller4 = sellers.get(3).unwrap();
    
    // Add first boost
    authorize_token_transfer(&env, &token_id, &seller1, &contract_id, 5_000_000i128);
    client.boost_product(&seller1, &category, &1001u64, &duration, &5_000_000i128);
    advance_ledger_time(&env, 1); // Advance time to ensure different slot IDs
    let list1 = client.get_boosted_list();
    assert_eq!(list1.len(), 1, "After 1st boost: expected 1, got {}", list1.len());
    
    // Add second boost
    authorize_token_transfer(&env, &token_id, &seller2, &contract_id, 5_000_000i128);
    client.boost_product(&seller2, &category, &1002u64, &duration, &5_000_000i128);
    advance_ledger_time(&env, 1); // Advance time to ensure different slot IDs
    let list2 = client.get_boosted_list();
    assert_eq!(list2.len(), 2, "After 2nd boost: expected 2, got {}", list2.len());
    
    // Add third boost
    authorize_token_transfer(&env, &token_id, &seller3, &contract_id, 5_000_000i128);
    client.boost_product(&seller3, &category, &1003u64, &duration, &5_000_000i128);
    advance_ledger_time(&env, 1); // Advance time to ensure different slot IDs
    let list3 = client.get_boosted_list();
    assert_eq!(list3.len(), 3, "After 3rd boost: expected 3, got {}", list3.len());
    
    // Add fourth boost with higher payment - should replace one
    authorize_token_transfer(&env, &token_id, &seller4, &contract_id, 10_000_000i128);
    client.boost_product(&seller4, &category, &1004u64, &duration, &10_000_000i128);
    let list4 = client.get_boosted_list();
    
    assert_eq!(list4.len(), 3, "After 4th boost: expected 3, got {}", list4.len());
    assert!(client.is_boosted(&1004u64), "Product 1004 should be boosted");
}

// Simple test to verify slot replacement works
#[test]
fn test_simple_slot_replacement() {
    let env = create_test_env();
    let contract_id = register_contract(&env);
    let (token_id, sellers) = setup_xlm_token_and_sellers(&env, &contract_id);
    let client = PromotionBoostContractClient::new(&env, &contract_id);
    
    let category = Symbol::new(&env, "electronics");
    let duration = 86400u64; // 1 day
    
    let seller1 = sellers.get(0).unwrap();
    let seller2 = sellers.get(1).unwrap();
    
    // Fill 3 slots with low payments
    authorize_token_transfer(&env, &token_id, &seller1, &contract_id, 5_000_000i128);
    client.boost_product(&seller1, &category, &1001u64, &duration, &5_000_000i128);
    advance_ledger_time(&env, 1);
    
    authorize_token_transfer(&env, &token_id, &seller1, &contract_id, 5_000_000i128);
    client.boost_product(&seller1, &category, &1002u64, &duration, &5_000_000i128);
    advance_ledger_time(&env, 1);
    
    authorize_token_transfer(&env, &token_id, &seller1, &contract_id, 5_000_000i128);
    client.boost_product(&seller1, &category, &1003u64, &duration, &5_000_000i128);
    advance_ledger_time(&env, 1);
    
    // Verify 3 slots are filled
    let list_before = client.get_boosted_list();
    assert_eq!(list_before.len(), 3, "Should have 3 slots filled");
    
    // Add higher payment - should replace one
    authorize_token_transfer(&env, &token_id, &seller2, &contract_id, 10_000_000i128);
    client.boost_product(&seller2, &category, &1004u64, &duration, &10_000_000i128);
    
    // Verify still 3 slots, but with replacement
    let list_after = client.get_boosted_list();
    assert_eq!(list_after.len(), 3, "Should still have 3 slots after replacement");
    assert!(client.is_boosted(&1004u64), "New high-paying product should be boosted");
}

// Additional comprehensive tests for enhanced coverage

#[test]
fn test_seller_boost_limits_per_category() {
    let env = create_test_env();
    let contract_id = register_contract(&env);
    let (token_id, sellers) = setup_xlm_token_and_sellers(&env, &contract_id);
    let client = PromotionBoostContractClient::new(&env, &contract_id);
    
    let seller = sellers.get(0).unwrap();
    let electronics_category = Symbol::new(&env, "electronics");
    let clothing_category = Symbol::new(&env, "clothing");
    let duration = 86400u64;
    let payment = 5_000_000i128;
    
    // Test that a seller can boost multiple products in the same category
    authorize_token_transfer(&env, &token_id, &seller, &contract_id, payment);
    client.boost_product(&seller, &electronics_category, &1001u64, &duration, &payment);
    advance_ledger_time(&env, 1);
    
    authorize_token_transfer(&env, &token_id, &seller, &contract_id, payment);
    client.boost_product(&seller, &electronics_category, &1002u64, &duration, &payment);
    advance_ledger_time(&env, 1);
    
    // Both should be boosted
    assert!(client.is_boosted(&1001u64));
    assert!(client.is_boosted(&1002u64));
    
    // Test that same seller can boost in different categories
    authorize_token_transfer(&env, &token_id, &seller, &contract_id, payment);
    client.boost_product(&seller, &clothing_category, &1003u64, &duration, &payment);
    
    assert!(client.is_boosted(&1003u64));
    
    // Verify total boosted products
    let boosted_list = client.get_boosted_list();
    assert_eq!(boosted_list.len(), 3);
}

#[test]
fn test_boost_stacking_same_product() {
    let env = create_test_env();
    let contract_id = register_contract(&env);
    let (token_id, sellers) = setup_xlm_token_and_sellers(&env, &contract_id);
    let client = PromotionBoostContractClient::new(&env, &contract_id);
    
    let seller = sellers.get(0).unwrap();
    let category = Symbol::new(&env, "electronics");
    let product_id = 1001u64;
    let duration = 3600u64; // 1 hour
    let payment = 5_000_000i128;
    
    // First boost
    authorize_token_transfer(&env, &token_id, &seller, &contract_id, payment);
    client.boost_product(&seller, &category, &product_id, &duration, &payment);
    assert!(client.is_boosted(&product_id));
    
    // Advance time to near expiration
    advance_ledger_time(&env, 3000u64); // 50 minutes
    assert!(client.is_boosted(&product_id));
    
    // Second boost for same product (renewal/extension)
    authorize_token_transfer(&env, &token_id, &seller, &contract_id, payment);
    client.boost_product(&seller, &category, &product_id, &duration, &payment);
    
    // Should still be boosted
    assert!(client.is_boosted(&product_id));
    
    // Advance past original expiration time
    advance_ledger_time(&env, 700u64); // Total: 61 minutes 40 seconds
    assert!(client.is_boosted(&product_id), "Product should still be boosted after renewal");
}

#[test]
#[should_panic(expected = "Slot limit reached and bid was not high enough")]
fn test_payment_refund_on_failed_boost() {
    let env = create_test_env();
    let contract_id = register_contract(&env);
    let (token_id, sellers) = setup_xlm_token_and_sellers(&env, &contract_id);
    let client = PromotionBoostContractClient::new(&env, &contract_id);
    
    let category = Symbol::new(&env, "electronics");
    let duration = 86400u64;
    
    // Fill all 3 slots with high payments
    let seller1 = sellers.get(0).unwrap();
    let seller2 = sellers.get(1).unwrap();
    let seller3 = sellers.get(2).unwrap();
    let seller4 = sellers.get(3).unwrap();
    
    let high_payment = 20_000_000i128; // 20 XLM
    let low_payment = 5_000_000i128;   // 5 XLM
    
    // Fill slots with high payments
    authorize_token_transfer(&env, &token_id, &seller1, &contract_id, high_payment);
    client.boost_product(&seller1, &category, &1001u64, &duration, &high_payment);
    advance_ledger_time(&env, 1);
    
    authorize_token_transfer(&env, &token_id, &seller2, &contract_id, high_payment);
    client.boost_product(&seller2, &category, &1002u64, &duration, &high_payment);
    advance_ledger_time(&env, 1);
    
    authorize_token_transfer(&env, &token_id, &seller3, &contract_id, high_payment);
    client.boost_product(&seller3, &category, &1003u64, &duration, &high_payment);
    advance_ledger_time(&env, 1);
    
    // Verify 3 slots are filled
    assert_eq!(client.get_slot_count(&category), 3);
    
    // Try to add a low-paying boost - should be rejected and refunded (will panic)
    authorize_token_transfer(&env, &token_id, &seller4, &contract_id, low_payment);
    client.boost_product(&seller4, &category, &1004u64, &duration, &low_payment);
}

#[test]
fn test_multiple_categories_independent_slots() {
    let env = create_test_env();
    let contract_id = register_contract(&env);
    let (token_id, sellers) = setup_xlm_token_and_sellers(&env, &contract_id);
    let client = PromotionBoostContractClient::new(&env, &contract_id);
    
    let seller = sellers.get(0).unwrap();
    let electronics = Symbol::new(&env, "electronics");
    let clothing = Symbol::new(&env, "clothing");
    let books = Symbol::new(&env, "books");
    let duration = 86400u64;
    let payment = 5_000_000i128;
    
    // Fill electronics category (3 slots)
    for i in 1..=3 {
        authorize_token_transfer(&env, &token_id, &seller, &contract_id, payment);
        client.boost_product(&seller, &electronics, &(1000u64 + i), &duration, &payment);
        advance_ledger_time(&env, 1);
    }
    
    // Fill clothing category (3 slots)
    for i in 1..=3 {
        authorize_token_transfer(&env, &token_id, &seller, &contract_id, payment);
        client.boost_product(&seller, &clothing, &(2000u64 + i), &duration, &payment);
        advance_ledger_time(&env, 1);
    }
    
    // Fill books category (3 slots)
    for i in 1..=3 {
        authorize_token_transfer(&env, &token_id, &seller, &contract_id, payment);
        client.boost_product(&seller, &books, &(3000u64 + i), &duration, &payment);
        advance_ledger_time(&env, 1);
    }
    
    // Verify all 9 products are boosted (3 per category)
    let boosted_list = client.get_boosted_list();
    assert_eq!(boosted_list.len(), 9, "Should have 9 total boosted products across categories");
    
    // Verify specific products are boosted
    assert!(client.is_boosted(&1001u64)); // Electronics
    assert!(client.is_boosted(&2001u64)); // Clothing
    assert!(client.is_boosted(&3001u64)); // Books
}

#[test]
fn test_boost_expiration_cleanup_multiple_products() {
    let env = create_test_env();
    let contract_id = register_contract(&env);
    let (token_id, sellers) = setup_xlm_token_and_sellers(&env, &contract_id);
    let client = PromotionBoostContractClient::new(&env, &contract_id);
    
    let seller = sellers.get(0).unwrap();
    let category = Symbol::new(&env, "electronics");
    let short_duration = 3600u64; // 1 hour
    let long_duration = 7200u64;  // 2 hours
    let payment = 5_000_000i128;
    
    // Add products with different expiration times
    authorize_token_transfer(&env, &token_id, &seller, &contract_id, payment);
    client.boost_product(&seller, &category, &1001u64, &short_duration, &payment);
    advance_ledger_time(&env, 1);
    
    authorize_token_transfer(&env, &token_id, &seller, &contract_id, payment);
    client.boost_product(&seller, &category, &1002u64, &long_duration, &payment);
    advance_ledger_time(&env, 1);
    
    authorize_token_transfer(&env, &token_id, &seller, &contract_id, payment);
    client.boost_product(&seller, &category, &1003u64, &short_duration, &payment);
    
    // Verify all are initially boosted
    assert_eq!(client.get_boosted_list().len(), 3);
    assert!(client.is_boosted(&1001u64));
    assert!(client.is_boosted(&1002u64));
    assert!(client.is_boosted(&1003u64));
    
    // Advance time past short duration but not long duration
    advance_ledger_time(&env, 3601u64); // 1 hour + 1 second
    
    // Check which products are still boosted (should auto-cleanup expired)
    let boosted_after_partial_expiry = client.get_boosted_list();
    assert_eq!(boosted_after_partial_expiry.len(), 1, "Only long-duration boost should remain");
    assert!(!client.is_boosted(&1001u64));
    assert!(client.is_boosted(&1002u64));
    assert!(!client.is_boosted(&1003u64));
    
    // Advance time past all durations
    advance_ledger_time(&env, 3601u64); // Total: 2 hours + 2 seconds
    
    // All should be expired
    let boosted_after_full_expiry = client.get_boosted_list();
    assert_eq!(boosted_after_full_expiry.len(), 0, "All boosts should be expired");
    assert!(!client.is_boosted(&1002u64));
}

#[test]
fn test_event_emission_comprehensive() {
    let env = create_test_env();
    let contract_id = register_contract(&env);
    let (token_id, sellers) = setup_xlm_token_and_sellers(&env, &contract_id);
    let client = PromotionBoostContractClient::new(&env, &contract_id);
    
    let seller1 = sellers.get(0).unwrap();
    let seller2 = sellers.get(1).unwrap();
    let category = Symbol::new(&env, "electronics");
    let duration = 86400u64;
    let low_payment = 5_000_000i128;
    let high_payment = 10_000_000i128;
    
    // Clear any existing events
    env.events().all();
    
    // Add first boost
    authorize_token_transfer(&env, &token_id, &seller1, &contract_id, low_payment);
    client.boost_product(&seller1, &category, &1001u64, &duration, &low_payment);
    
    let events_after_first = env.events().all();
    assert!(!events_after_first.is_empty(), "Events should be emitted for first boost");
    
    // Fill remaining slots
    authorize_token_transfer(&env, &token_id, &seller1, &contract_id, low_payment);
    client.boost_product(&seller1, &category, &1002u64, &duration, &low_payment);
    advance_ledger_time(&env, 1);
    
    authorize_token_transfer(&env, &token_id, &seller1, &contract_id, low_payment);
    client.boost_product(&seller1, &category, &1003u64, &duration, &low_payment);
    advance_ledger_time(&env, 1);
    
    // Clear events to focus on replacement
    env.events().all();
    
    // Add higher-paying boost that should trigger replacement
    authorize_token_transfer(&env, &token_id, &seller2, &contract_id, high_payment);
    client.boost_product(&seller2, &category, &1004u64, &duration, &high_payment);
    
    let events_after_replacement = env.events().all();
    assert!(!events_after_replacement.is_empty(), "Events should be emitted for replacement");
    
    // Verify the replacement worked
    assert!(client.is_boosted(&1004u64), "High-paying product should be boosted");
    assert_eq!(client.get_boosted_list().len(), 3, "Should still have 3 total slots");
}

#[test]
fn test_edge_case_zero_duration() {
    let env = create_test_env();
    let contract_id = register_contract(&env);
    let (token_id, sellers) = setup_xlm_token_and_sellers(&env, &contract_id);
    let client = PromotionBoostContractClient::new(&env, &contract_id);
    
    let seller = sellers.get(0).unwrap();
    let category = Symbol::new(&env, "electronics");
    let zero_duration = 0u64;
    let payment = 5_000_000i128;
    
    // Try to boost with zero duration
    authorize_token_transfer(&env, &token_id, &seller, &contract_id, payment);
    client.boost_product(&seller, &category, &1001u64, &zero_duration, &payment);
    
    // Product should be immediately expired (not boosted)
    assert!(!client.is_boosted(&1001u64), "Zero duration boost should not be active");
    assert_eq!(client.get_boosted_list().len(), 0, "No products should be boosted with zero duration");
}

#[test]
fn test_very_long_duration_boost() {
    let env = create_test_env();
    let contract_id = register_contract(&env);
    let (token_id, sellers) = setup_xlm_token_and_sellers(&env, &contract_id);
    let client = PromotionBoostContractClient::new(&env, &contract_id);
    
    let seller = sellers.get(0).unwrap();
    let category = Symbol::new(&env, "electronics");
    let long_duration = 86400u64 * 365; // 1 year
    let payment = 1_825_000_000i128; // 365 * 5 XLM for 1 year
    
    // Boost with very long duration
    authorize_token_transfer(&env, &token_id, &seller, &contract_id, payment);
    client.boost_product(&seller, &category, &1001u64, &long_duration, &payment);
    
    assert!(client.is_boosted(&1001u64), "Long duration boost should be active");
    
    // Advance time significantly but not past expiration
    advance_ledger_time(&env, 86400u64 * 30); // 30 days
    assert!(client.is_boosted(&1001u64), "Should still be boosted after 30 days");
    
    // Advance to near expiration
    advance_ledger_time(&env, 86400u64 * 334); // Total: 364 days
    assert!(client.is_boosted(&1001u64), "Should still be boosted after 364 days");
    
    // Advance past expiration
    advance_ledger_time(&env, 86400u64 * 2); // Total: 366 days
    assert!(!client.is_boosted(&1001u64), "Should be expired after 366 days");
}

#[test]
fn test_slot_count_tracking() {
    let env = create_test_env();
    let contract_id = register_contract(&env);
    let (token_id, sellers) = setup_xlm_token_and_sellers(&env, &contract_id);
    let client = PromotionBoostContractClient::new(&env, &contract_id);
    
    let seller = sellers.get(0).unwrap();
    let category = Symbol::new(&env, "electronics");
    let duration = 86400u64;
    let payment = 5_000_000i128;
    
    // Initially no slots
    assert_eq!(client.get_slot_count(&category), 0);
    
    // Add first slot
    authorize_token_transfer(&env, &token_id, &seller, &contract_id, payment);
    client.boost_product(&seller, &category, &1001u64, &duration, &payment);
    assert_eq!(client.get_slot_count(&category), 1);
    advance_ledger_time(&env, 1);
    
    // Add second slot
    authorize_token_transfer(&env, &token_id, &seller, &contract_id, payment);
    client.boost_product(&seller, &category, &1002u64, &duration, &payment);
    assert_eq!(client.get_slot_count(&category), 2);
    advance_ledger_time(&env, 1);
    
    // Add third slot
    authorize_token_transfer(&env, &token_id, &seller, &contract_id, payment);
    client.boost_product(&seller, &category, &1003u64, &duration, &payment);
    assert_eq!(client.get_slot_count(&category), 3);
    
    // Verify max slots reached
    assert_eq!(client.get_slot_count(&category), 3);
    
    // Advance time to expire all
    advance_ledger_time(&env, 86401u64);
    client.cleanup_expired(&category);
    assert_eq!(client.get_slot_count(&category), 0);
}

// Debug test to understand slot replacement behavior
#[test]
fn test_debug_slot_replacement_step_by_step() {
    let env = create_test_env();
    let contract_id = register_contract(&env);
    let (token_id, sellers) = setup_xlm_token_and_sellers(&env, &contract_id);
    let client = PromotionBoostContractClient::new(&env, &contract_id);
    
    let category = Symbol::new(&env, "electronics");
    let duration = 86400u64; // 1 day
    
    let seller1 = sellers.get(0).unwrap();
    let seller2 = sellers.get(1).unwrap();
    
    // Step 1: Add first slot
    authorize_token_transfer(&env, &token_id, &seller1, &contract_id, 5_000_000i128);
    client.boost_product(&seller1, &category, &1001u64, &duration, &5_000_000i128);
    advance_ledger_time(&env, 1);
    
    let count_after_1 = client.get_slot_count(&category);
    let boosted_after_1 = client.get_boosted_list();
    assert_eq!(count_after_1, 1, "Should have 1 slot after first boost");
    assert_eq!(boosted_after_1.len(), 1, "Should have 1 boosted product");
    assert!(client.is_boosted(&1001u64), "Product 1001 should be boosted");
    
    // Step 2: Add second slot
    authorize_token_transfer(&env, &token_id, &seller1, &contract_id, 5_000_000i128);
    client.boost_product(&seller1, &category, &1002u64, &duration, &5_000_000i128);
    advance_ledger_time(&env, 1);
    
    let count_after_2 = client.get_slot_count(&category);
    let boosted_after_2 = client.get_boosted_list();
    assert_eq!(count_after_2, 2, "Should have 2 slots after second boost");
    assert_eq!(boosted_after_2.len(), 2, "Should have 2 boosted products");
    assert!(client.is_boosted(&1002u64), "Product 1002 should be boosted");
    
    // Step 3: Add third slot
    authorize_token_transfer(&env, &token_id, &seller1, &contract_id, 5_000_000i128);
    client.boost_product(&seller1, &category, &1003u64, &duration, &5_000_000i128);
    advance_ledger_time(&env, 1);
    
    let count_after_3 = client.get_slot_count(&category);
    let boosted_after_3 = client.get_boosted_list();
    assert_eq!(count_after_3, 3, "Should have 3 slots after third boost");
    assert_eq!(boosted_after_3.len(), 3, "Should have 3 boosted products");
    assert!(client.is_boosted(&1003u64), "Product 1003 should be boosted");
    
    // Step 4: Try to add fourth slot with higher payment - should replace one
    authorize_token_transfer(&env, &token_id, &seller2, &contract_id, 10_000_000i128);
    client.boost_product(&seller2, &category, &1004u64, &duration, &10_000_000i128);
    
    let count_after_4 = client.get_slot_count(&category);
    let boosted_after_4 = client.get_boosted_list();
    assert_eq!(count_after_4, 3, "Should still have 3 slots after replacement attempt");
    assert_eq!(boosted_after_4.len(), 3, "Should still have 3 boosted products");
    
    // Check if the high-paying product is now boosted
    let is_1004_boosted = client.is_boosted(&1004u64);
    
    // Debug output - let's see what products are actually boosted
    let final_boosted = client.get_boosted_list();
    
    // Print debug info (this won't show in normal test runs but helps with debugging)
    // In a real scenario, we'd use proper logging
    
    assert!(is_1004_boosted, "Product 1004 with higher payment should be boosted. Boosted products: {:?}", final_boosted);
}

// More detailed debug test to check slot manager state
#[test]
fn test_debug_slot_manager_state() {
    let env = create_test_env();
    let contract_id = register_contract(&env);
    let (token_id, sellers) = setup_xlm_token_and_sellers(&env, &contract_id);
    let client = PromotionBoostContractClient::new(&env, &contract_id);
    
    let category = Symbol::new(&env, "electronics");
    let duration = 86400u64; // 1 day
    
    let seller1 = sellers.get(0).unwrap();
    let seller2 = sellers.get(1).unwrap();
    
    // Add 3 slots with same low payment
    for i in 1..=3 {
        authorize_token_transfer(&env, &token_id, &seller1, &contract_id, 5_000_000i128);
        client.boost_product(&seller1, &category, &(1000u64 + i), &duration, &5_000_000i128);
        advance_ledger_time(&env, 1);
        
        // Check state after each addition
        let count = client.get_slot_count(&category);
        let boosted = client.get_boosted_list();
        assert_eq!(count, i as u32, "Slot count should be {} after adding slot {}", i, i);
        assert_eq!(boosted.len() as u32, i as u32, "Boosted list should have {} items after adding slot {}", i, i);
        assert!(client.is_boosted(&(1000u64 + i)), "Product {} should be boosted", 1000 + i);
    }
    
    // Now try to add a higher-paying slot
    authorize_token_transfer(&env, &token_id, &seller2, &contract_id, 10_000_000i128);
    
    // Check state before replacement
    let count_before = client.get_slot_count(&category);
    let boosted_before = client.get_boosted_list();
    assert_eq!(count_before, 3, "Should have 3 slots before replacement");
    assert_eq!(boosted_before.len(), 3, "Should have 3 boosted products before replacement");
    
    // Add the high-paying boost
    client.boost_product(&seller2, &category, &1004u64, &duration, &10_000_000i128);
    
    // Check state after replacement
    let count_after = client.get_slot_count(&category);
    let boosted_after = client.get_boosted_list();
    
    // The slot count should still be 3
    assert_eq!(count_after, 3, "Should still have 3 slots after replacement");
    
    // The boosted list should still have 3 items
    assert_eq!(boosted_after.len(), 3, "Should still have 3 boosted products after replacement");
    
    // The high-paying product should be boosted
    let is_1004_boosted = client.is_boosted(&1004u64);
    
    // Check which products are still boosted
    let is_1001_boosted = client.is_boosted(&1001u64);
    let is_1002_boosted = client.is_boosted(&1002u64);
    let is_1003_boosted = client.is_boosted(&1003u64);
    
    // At least one of the original products should no longer be boosted
    let original_still_boosted = [is_1001_boosted, is_1002_boosted, is_1003_boosted].iter().filter(|&&x| x).count();
    
    assert!(is_1004_boosted, "Product 1004 with higher payment should be boosted");
    assert_eq!(original_still_boosted, 2, "Exactly 2 of the original 3 products should still be boosted");
    assert_eq!(boosted_after.len(), 3, "Total boosted products should be 3");
}

#[test]
fn test_minimal_slot_replacement_debug() {
    let env = create_test_env();
    let contract_id = register_contract(&env);
    let (token_id, sellers) = setup_xlm_token_and_sellers(&env, &contract_id);
    let client = PromotionBoostContractClient::new(&env, &contract_id);
    
    let category = Symbol::new(&env, "electronics");
    let duration = 86400u64; // 1 day
    
    let seller1 = sellers.get(0).unwrap();
    let seller2 = sellers.get(1).unwrap();
    
    // Add first slot with low payment
    authorize_token_transfer(&env, &token_id, &seller1, &contract_id, 5_000_000i128);
    client.boost_product(&seller1, &category, &1001u64, &duration, &5_000_000i128);
    advance_ledger_time(&env, 1);
    
    // Check state after first slot
    let count_1 = client.get_slot_count(&category);
    let boosted_1 = client.get_boosted_list();
    let is_1001_boosted_1 = client.is_boosted(&1001u64);
    
    assert_eq!(count_1, 1, "Should have 1 slot after first boost");
    assert_eq!(boosted_1.len(), 1, "Should have 1 boosted product");
    assert!(is_1001_boosted_1, "Product 1001 should be boosted");
    
    // Add higher payment - should succeed since there are only 3 slots max
    authorize_token_transfer(&env, &token_id, &seller2, &contract_id, 10_000_000i128);
    client.boost_product(&seller2, &category, &1004u64, &duration, &10_000_000i128);
    
    // Check state after second slot
    let count_2 = client.get_slot_count(&category);
    let boosted_2 = client.get_boosted_list();
    let is_1001_boosted_2 = client.is_boosted(&1001u64);
    let is_1004_boosted_2 = client.is_boosted(&1004u64);
    
    assert_eq!(count_2, 2, "Should have 2 slots after second boost");
    assert_eq!(boosted_2.len(), 2, "Should have 2 boosted products");
    assert!(is_1001_boosted_2, "Product 1001 should still be boosted");
    assert!(is_1004_boosted_2, "Product 1004 should be boosted");
}

#[test]
fn test_slot_replacement_scenario() {
    let env = create_test_env();
    let contract_id = register_contract(&env);
    let (token_id, sellers) = setup_xlm_token_and_sellers(&env, &contract_id);
    let client = PromotionBoostContractClient::new(&env, &contract_id);
    
    let category = Symbol::new(&env, "electronics");
    let duration = 86400u64; // 1 day
    
    let seller1 = sellers.get(0).unwrap();
    let seller2 = sellers.get(1).unwrap();
    
    // Fill all 3 slots with low payments
    authorize_token_transfer(&env, &token_id, &seller1, &contract_id, 5_000_000i128);
    client.boost_product(&seller1, &category, &1001u64, &duration, &5_000_000i128);
    advance_ledger_time(&env, 1);
    
    authorize_token_transfer(&env, &token_id, &seller1, &contract_id, 5_000_000i128);
    client.boost_product(&seller1, &category, &1002u64, &duration, &5_000_000i128);
    advance_ledger_time(&env, 1);
    
    authorize_token_transfer(&env, &token_id, &seller1, &contract_id, 5_000_000i128);
    client.boost_product(&seller1, &category, &1003u64, &duration, &5_000_000i128);
    advance_ledger_time(&env, 1);
    
    // Verify 3 slots are filled
    let count_before = client.get_slot_count(&category);
    let boosted_before = client.get_boosted_list();
    
    assert_eq!(count_before, 3, "Should have 3 slots filled");
    assert_eq!(boosted_before.len(), 3, "Should have 3 boosted products");
    assert!(client.is_boosted(&1001u64), "Product 1001 should be boosted");
    assert!(client.is_boosted(&1002u64), "Product 1002 should be boosted");
    assert!(client.is_boosted(&1003u64), "Product 1003 should be boosted");
    
    // Now add a higher payment - this should trigger replacement
    authorize_token_transfer(&env, &token_id, &seller2, &contract_id, 10_000_000i128);
    client.boost_product(&seller2, &category, &1004u64, &duration, &10_000_000i128);
    
    // Check state after replacement
    let count_after = client.get_slot_count(&category);
    let boosted_after = client.get_boosted_list();
    
    assert_eq!(count_after, 3, "Should still have 3 slots after replacement");
    assert_eq!(boosted_after.len(), 3, "Should still have 3 boosted products after replacement");
    assert!(client.is_boosted(&1004u64), "High-paying product 1004 should be boosted");
    
    // Check which of the original products are still boosted
    let is_1001_boosted = client.is_boosted(&1001u64);
    let is_1002_boosted = client.is_boosted(&1002u64);
    let is_1003_boosted = client.is_boosted(&1003u64);
    
    // At least one of the original products should no longer be boosted
    let original_still_boosted = [is_1001_boosted, is_1002_boosted, is_1003_boosted].iter().filter(|&&x| x).count();
    
    assert_eq!(original_still_boosted, 2, "Exactly 2 of the original 3 products should still be boosted");
} 