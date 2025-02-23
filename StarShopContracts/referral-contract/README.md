# Multi-Level Referral Smart Contract

A Soroban smart contract implementing a sophisticated multi-level referral
system with reward tracking, commission distribution, and user verification.

## 🌟 Features

### Referral System

- Multi-level referral tracking (up to 3 levels)
- Automatic commission distribution
- Team size tracking across levels
- Verified referrer requirements

### User Levels

- 4-tier system: Basic → Silver → Gold → Platinum
- Automatic level progression
- Configurable requirements per level:
  - Direct referrals count
  - Team size
  - Total rewards earned

### Reward Structure

- Tiered commission rates:
  - Level 1: 5% (configurable)
  - Level 2: 2% (configurable)
  - Level 3: 1% (configurable)
- Milestone-based rewards
- Reward caps per referral
- Automatic distribution

### Verification System

- KYC verification requirement
- Admin approval process
- Verification status tracking
- Identity proof storage

### Security Features

- Contract pause mechanism
- Admin controls
- Authorization checks
- Duplicate prevention
- Activity tracking

## 📋 Prerequisites

- Rust toolchain
- Soroban CLI

## 🛠 Setup

1. Install dependencies:

```bash
make build
```

## 📝 Contract Interface

### Admin Operations

```rust
fn initialize(env: Env, admin: Address, reward_token: Address) -> Result<(), Error>
fn set_reward_rates(env: Env, rates: RewardRates) -> Result<(), Error>
fn set_level_requirements(env: Env, requirements: LevelRequirements) -> Result<(), Error>
fn pause_contract(env: Env) -> Result<(), Error>
fn resume_contract(env: Env) -> Result<(), Error>
```

### User Operations

```rust
fn register_with_referral(env: Env, user: Address, referrer: Address, identity_proof: String) -> Result<(), Error>
fn submit_verification(env: Env, user: Address, identity_proof: String) -> Result<(), Error>
fn claim_rewards(env: Env, user: Address) -> Result<i128, Error>
```

### Query Operations

```rust
fn get_user_info(env: Env, user: Address) -> Result<UserData, Error>
fn get_pending_rewards(env: Env, user: Address) -> Result<i128, Error>
fn get_verification_status(env: Env, user: Address) -> Result<VerificationStatus, Error>
```

## 🏗 Contract Structure

```text
referral-contract/
├── src/
│   ├── lib.rs           # Contract entry points
│   ├── admin.rs         # Admin operations
│   ├── referral.rs      # Referral logic
│   ├── rewards.rs       # Reward management
│   ├── verification.rs  # User verification
│   ├── level.rs         # Level management
│   ├── types.rs         # Data structures
│   ├── helpers.rs       # Utility functions
│   └── test.rs          # Test suite
└── Cargo.toml
```

## 🔄 User Flow

1. User Registration
   - Register with referrer
   - Submit verification documents
   - Await verification approval

2. Level Progression
   - Meet level requirements
   - Automatic level upgrades
   - Access level benefits

3. Reward Distribution
   - Earn commissions from referrals
   - Achieve milestones
   - Claim rewards

## 🔐 Security Considerations

- All critical operations require verification
- Admin operations are protected
- Reward caps prevent abuse
- Pause mechanism for emergencies

## 📊 Metrics & Analytics

- Total users tracking
- Reward distribution stats
- Referral conversion rates
- Level distribution
- System performance metrics

## 🧪 Testing

Run the test suite:

```bash
make test
```
