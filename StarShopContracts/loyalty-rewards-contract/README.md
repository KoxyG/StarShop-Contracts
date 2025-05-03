# Loyalty Rewards Contract

A Soroban smart contract for managing a comprehensive loyalty rewards program where users earn points for purchases and activities, which can be redeemed for discounts, products, or token rewards.

## Features

- **Points Management**: Earn points for purchases, track balances, and handle point expiration
- **Loyalty Levels**: Bronze, Silver, and Gold tiers with increasing benefits
- **Milestones**: Special achievements that grant bonus points
- **Rewards System**: Redeem points for discounts, products, or token rewards
- **Anti-Fraud Protection**: Limits on redemption and point earning

## Project Structure

```text
.
├── loyalty-rewards
│   └── src
│       ├── admin.rs       // Admin functionality and configuration hola
│       ├── levels.rs      // Loyalty level management
│       ├── lib.rs         // Main contract interface
│       ├── milestones.rs  // Milestone tracking and rewards
│       ├── points.rs      // Points earning and management
│       ├── rewards.rs     // Redemption system
│       ├── test.rs        // Unit tests
│       └── types.rs       // Data structures and error types
│   ├── Cargo.toml
│   ├── Makefile
│   └── README.md
```

## Contract Interface

The contract exposes the following main functions:

### Admin Functions
- `init`: Initialize the contract with an admin
- `set_points_expiry`: Set the expiration period for points
- `set_max_redemption_percentage`: Set maximum percentage of purchase that can be paid with points
- `set_points_ratio`: Set points earned per purchase amount
- `set_category_bonus`: Set bonus points for product categories
- `set_product_bonus`: Set bonus points for specific products

### Points Management
- `register_user`: Register a new user in the system
- `add_points`: Add points to a user's account
- `get_points_balance`: Get user's current points balance
- `get_lifetime_points`: Get user's total earned points
- `record_purchase_points`: Record points for a purchase

### Levels Management
- `init_level_requirements`: Set requirements for each loyalty level
- `check_and_update_level`: Check and update user's loyalty level
- `get_user_level`: Get user's current loyalty level
- `award_anniversary_bonus`: Award bonus points for level anniversaries

### Milestones Management
- `create_milestone`: Create a new milestone
- `complete_milestone`: Complete a milestone and award points
- `check_and_complete_milestones`: Check all milestones for a user

### Rewards Management
- `create_reward`: Create a new reward
- `redeem_reward`: Redeem a reward with points
- `get_available_rewards`: Get available rewards for a user
- `calculate_discount`: Calculate discount amount for a purchase
