# Crowdfunding Collective Smart Contract

A Soroban smart contract implementing a comprehensive crowdfunding platform with milestone tracking, reward tiers, and automated fund distribution.

## 🌟 Features

### Product Crowdfunding
- **Project Creation**: Launch crowdfunding campaigns for products
- **Funding Goals**: Set target funding amounts with deadlines
- **Progress Tracking**: Real-time funding progress monitoring
- **Status Management**: Automatic status updates based on funding progress

### Contribution System
- **Flexible Contributions**: Accept various contribution amounts
- **Contributor Tracking**: Complete contribution history
- **Automatic Processing**: Instant contribution processing
- **Refund Protection**: Automatic refunds for failed campaigns

### Reward Tiers
- **Tiered Rewards**: Multiple reward levels based on contribution amounts
- **Discount System**: Percentage-based reward discounts
- **Eligibility Tracking**: Automatic reward tier assignment
- **Claim Management**: Secure reward claiming process

### Milestone Tracking
- **Development Milestones**: Track project development progress
- **Target Dates**: Set expected completion dates
- **Progress Updates**: Creator-driven milestone updates
- **Completion Validation**: Verified milestone completion

### Fund Management
- **Escrow System**: Secure fund holding until goals are met
- **Automated Distribution**: Smart contract-based fund release
- **Refund Processing**: Automatic refunds for failed projects
- **Fee Management**: Transparent fee structure

## 📋 Prerequisites

- Rust toolchain
- Soroban CLI
- XLM for contributions

## 🛠 Setup

Install dependencies:
```bash
make build
```

## 📝 Contract Interface

### Admin Operations
```rust
fn initialize(env: Env, admin: Address)
```

### Product Management
```rust
fn create_product(
    env: Env,
    creator: Address,
    name: String,
    description: String,
    funding_goal: u64,
    deadline: u64,
    reward_tiers: Vec<RewardTier>,
    milestones: Vec<Milestone>
) -> u32
```

### Funding Operations
```rust
fn contribute(env: Env, contributor: Address, product_id: u32, amount: u64)
fn distribute_funds(env: Env, product_id: u32)
fn refund_contributors(env: Env, product_id: u32)
```

### Reward Operations
```rust
fn claim_reward(env: Env, contributor: Address, product_id: u32)
```

### Tracking Operations
```rust
fn update_milestone(env: Env, creator: Address, product_id: u32, milestone_id: u32)
fn get_product(env: Env, product_id: u32) -> Product
fn get_contributions(env: Env, product_id: u32) -> Vec<Contribution>
fn get_milestones(env: Env, product_id: u32) -> Vec<Milestone>
fn get_reward_tiers(env: Env, product_id: u32) -> Vec<RewardTier>
```

## 🏗 Contract Structure

```
crowdfunding-collective/
├── src/
│   ├── lib.rs           # Contract entry points
│   ├── product.rs       # Product creation & management
│   ├── funding.rs       # Contribution & fund management
│   ├── rewards.rs       # Reward tier management
│   ├── tracking.rs      # Milestone & progress tracking
│   ├── types.rs         # Data structures
│   └── test.rs          # Test suite
└── Cargo.toml
```

## 🔄 Crowdfunding Flow

1. **Project Creation**
   - Creator defines product details
   - Set funding goals and deadlines
   - Configure reward tiers
   - Define development milestones

2. **Funding Phase**
   - Contributors make pledges
   - Real-time progress tracking
   - Automatic goal checking
   - Contribution validation

3. **Success/Failure Handling**
   - **Success**: Funds distributed to creator
   - **Failure**: Automatic contributor refunds
   - Status updates and notifications

4. **Reward Distribution**
   - Eligible contributors claim rewards
   - Discount application
   - Reward tier validation

5. **Milestone Tracking**
   - Creator updates development progress
   - Milestone completion verification
   - Progress transparency for contributors

## 🎯 Product Status Flow

```
Active → Funded → Completed
   ↓
 Failed (if deadline passed without funding goal)
```

| Status | Description | Actions Available |
|--------|-------------|------------------|
| Active | Accepting contributions | Contribute, Update milestones |
| Funded | Goal reached, funds distributed | Update milestones, Claim rewards |
| Failed | Deadline passed without goal | Refund contributors |
| Completed | All milestones completed | Claim rewards |

## 💰 Reward Tier System

### Tier Structure
- **Minimum Contribution**: Required amount for tier eligibility
- **Description**: Reward details and benefits
- **Discount Percentage**: Discount on final product (0-100%)

### Example Tiers
| Tier | Min Contribution | Discount | Description |
|------|-----------------|----------|-------------|
| Bronze | 10 XLM | 5% | Early access + 5% discount |
| Silver | 50 XLM | 15% | Beta access + 15% discount |
| Gold | 100 XLM | 25% | Exclusive features + 25% discount |

## 🚫 Error Handling

### Common Validations
- **Funding Goal**: Must be greater than zero
- **Deadline**: Must be in the future
- **Contribution Amount**: Must be greater than zero
- **Authorization**: Contributors and creators must authorize actions
- **Status Checks**: Actions only available in appropriate status

### Error Prevention
- **Duplicate Contributions**: Prevented through proper validation
- **Invalid Amounts**: Comprehensive amount validation
- **Unauthorized Actions**: Strict authorization checks
- **Timeline Violations**: Deadline enforcement

## 📊 Data Structures

### Product
- **ID**: Unique product identifier
- **Creator**: Product creator address
- **Name & Description**: Product details
- **Funding Goal**: Target funding amount
- **Deadline**: Funding deadline
- **Status**: Current product status
- **Total Funded**: Amount raised so far

### Contribution
- **Contributor**: Contributor's address
- **Amount**: Contribution amount
- **Timestamp**: Contribution time

### Milestone
- **ID**: Unique milestone identifier
- **Description**: Milestone details
- **Target Date**: Expected completion date
- **Completed**: Completion status

## 🔐 Security Considerations

- **Authorization Checks**: All operations require proper authorization
- **Fund Safety**: Secure escrow until goals are met
- **Refund Protection**: Automatic refunds for failed campaigns
- **Creator Validation**: Only creators can update their projects
- **Contribution Limits**: Prevents funding goal exceeded
- **Timeline Enforcement**: Strict deadline adherence

## 🧪 Testing

Run the test suite:
```bash
make test
```

## 🎯 Use Cases

- **Product Development**: Fund new product development
- **Creative Projects**: Support artistic and creative endeavors
- **Technology Innovation**: Fund technological breakthroughs
- **Community Projects**: Support community-driven initiatives
- **Startup Funding**: Early-stage startup funding
- **Social Causes**: Fund social and environmental projects 