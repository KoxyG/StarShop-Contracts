# Multi-Level Referral Smart Contract

A Soroban smart contract implementing a sophisticated multi-level referral
system with reward tracking, commission distribution, and user verification.

## 🌟 Features

### Referral System

- **Multi-level referral tracking** (up to 3 levels)
- **Automatic commission distribution**
- **Team size tracking across levels**
- **Verified referrer requirements**

### User Levels

- **4-tier system**: Basic → Silver → Gold → Platinum
- **Automatic level progression**
- **Configurable requirements per level**:
  - Direct referrals count
  - Team size
  - Total rewards earned

### Reward Structure

- **Tiered commission rates**:
  - Level 1: 5% (configurable)
  - Level 2: 2% (configurable)
  - Level 3: 1% (configurable)
- **Milestone-based rewards**
- **Reward caps per referral**
- **Automatic distribution**

### Verification System

- **KYC verification requirement**
- **Admin approval process**
- **Verification status tracking**
- **Identity proof storage**

### Security Features

- **Contract pause mechanism**
- **Admin controls**
- **Authorization checks**
- **Duplicate prevention**
- **Activity tracking**

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
│   └── test.rs          # Test suite
└── Cargo.toml
```

## 🔄 User Flow

1. **User Registration**
   - Register with referrer
   - Submit verification documents
   - Await verification approval

2. **Level Progression**
   - Meet level requirements
   - Automatic level upgrades
   - Access level benefits

3. **Reward Distribution**
   - Earn commissions from referrals
   - Achieve milestones
   - Claim rewards

## 📊 Level System

| Level | Direct Referrals | Team Size | Total Rewards | Benefits |
|-------|-----------------|-----------|---------------|----------|
| Basic | 0 | 0 | 0 | Standard commission rates |
| Silver | 5 | 10 | 100 tokens | Enhanced commission rates |
| Gold | 15 | 50 | 1000 tokens | Premium commission rates |
| Platinum | 50 | 200 | 5000 tokens | Maximum commission rates |

## 💰 Commission Structure

### Default Rates
- **Level 1 (Direct)**: 5%
- **Level 2 (Indirect)**: 2%
- **Level 3 (Deep)**: 1%

### Level Multipliers
- **Basic**: 1.0x
- **Silver**: 1.2x
- **Gold**: 1.5x
- **Platinum**: 2.0x

## 🔐 Security Considerations

- **All critical operations require verification**
- **Admin operations are protected**
- **Reward caps prevent abuse**
- **Pause mechanism for emergencies**

## 📈 Verification Process

1. **Registration**: User provides identity proof
2. **Review**: Admin reviews verification documents
3. **Approval**: Admin approves or rejects verification
4. **Status Update**: User verification status updated
5. **Access Granted**: Verified users can participate in referral system

## 🚫 Error Handling

### Common Errors
- **Unauthorized**: Insufficient permissions
- **AlreadyExists**: User already registered
- **NotFound**: User or referrer not found
- **NotVerified**: User not verified for operation
- **InvalidInput**: Invalid parameters provided
- **ContractPaused**: Contract operations suspended

### Validation Checks
- **Referrer Verification**: Referrer must be verified
- **Self-Referral Prevention**: Users cannot refer themselves
- **Circular Reference Prevention**: Prevents circular referral chains
- **Duplicate Registration**: Prevents multiple registrations

## 📊 Metrics & Analytics

- **Total users tracking**
- **Reward distribution stats**
- **Referral conversion rates**
- **Level distribution**
- **System performance metrics**

## 🧪 Testing

Run the test suite:

```bash
make test
```

## 🎯 Use Cases

- **Affiliate Marketing**: Reward referrers for bringing new users
- **Network Marketing**: Multi-level marketing systems
- **User Acquisition**: Incentivize user growth
- **Community Building**: Build engaged user communities
- **Loyalty Programs**: Reward long-term user engagement
