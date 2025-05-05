# StarShop Promotional Boost Contract

## Overview
This contract allows sellers to “boost” visibility for their products by paying a fee. The boosted products appear in prioritized slots within a chosen category and remain there until their time duration expires or until they are replaced by another seller’s higher or more recent payment.

## Key Components
1. **Slots**  
   - Manages different boost slots by category.  
   - Stores mapping of category→slot IDs.  
   - Stores max allowed slots per category.  
   - Evicts existing slots if capacity is reached or time expires.

2. **Payments**  
   - Processes payments via the PaymentProcessor.  
   - Calculates and collects XLM for the boost duration.  
   - Refunds replaced sellers if a slot is overtaken.

3. **Visibility**  
   - Persists active boosts in a VisibilityManager.  
   - Flags a product as boosted and tracks the boost end time.  
   - Exposes methods to check if a product is boosted and retrieve active boosted products.

## Workflow
1. A seller calls `boost_product` with payment details.  
2. The contract calculates the needed payment, then collects XLM.  
3. A new slot is created or an existing one is overwritten if the limit is reached.  
4. If an old slot is replaced, the displaced seller is refunded.  
5. The contract updates internal records to reflect boosted products.  
6. Clients or external systems can query active boosts and handle them accordingly.

## Usage
- **Deployment**: Deploy the contract on a Soroban-compatible environment.  
- **Boosting a product**: Call `boost_product` with the seller’s address, category, product ID, duration, and payment amount.  
- **Checking boosts**: Use the `is_boosted` or `get_boosted_list` functions to retrieve active boosts.  
- **Cleaning up**: Admins can call `cleanup_expired` to remove expired slots and visibility records.

## Example
```
let result = PromotionBoostContract::boost_product(
    env,
    my_seller_address,
    category_symbol,
    product_id,
    duration_in_seconds,
    1000000i128, // Payment amount
);
```
This triggers payment collection, assigns a slot if available, and updates product visibility.

## Notes
- Time is derived from the ledger’s current timestamp.  
- Future improvements might include dynamic pricing strategies or additional payment currencies.  
- Thoroughly test changes to on-chain state, especially around slot replacement and refunds.

