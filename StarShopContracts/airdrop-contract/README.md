# Token Airdrop Smart Contract

A Soroban smart contract implementing a flexible token airdrop system with dynamic eligibility conditions, batch distribution, and comprehensive tracking.

## 🌟 Features

### Airdrop Management
- **Multi-Event Support**: Create and manage multiple airdrop campaigns
- **Dynamic Conditions**: Flexible eligibility criteria configuration
- **Token Flexibility**: Support for XLM and custom Stellar tokens
- **Time-Based Events**: Configurable start/end times for campaigns

### Eligibility System
- **Dynamic Conditions**: Configurable eligibility requirements
- **External Providers**: Integration with external data sources
- **Multi-Metric Support**: Multiple eligibility criteria per event
- **Real-Time Validation**: Live eligibility checking

### Distribution Methods
- **Individual Claims**: User-initiated token claiming
- **Batch Distribution**: Admin-triggered bulk distribution
- **Automatic Validation**: Built-in eligibility verification
- **Event Tracking**: Complete distribution audit trail

### Provider Integration
- **External Data Sources**: Connect to external metric providers
- **Provider Registry**: Manage multiple data providers
- **Dynamic Updates**: Update provider configurations
- **Fallback Mechanisms**: Handle provider failures gracefully

### Administrative Controls
- **Event Management**: Create, pause, resume, and finalize events
- **Provider Management**: Register and update metric providers
- **Access Control**: Secure admin operations
- **Emergency Controls**: Pause/resume functionality

## 📋 Prerequisites

- Rust toolchain
- Soroban CLI
- Stellar tokens for distribution

## 🛠 Setup

Install dependencies:
```bash
make build
```

## 📝 Contract Interface

### Admin Operations
```rust
fn initialize(
    env: Env, 
    admin: Address, 
    initial_providers: Option<Map<Symbol, Address>>
) -> Result<(), AirdropError>

fn create_airdrop(
    env: Env,
    admin: Address,
    name: Symbol,
    description: Bytes,
    conditions: Map<Symbol, u64>,
    amount: i128,
    token_address: Address,
    start_time: u64,
    end_time: u64,
    max_users: Option<u64>,
    max_total_amount: Option<i128>
) -> Result<u64, AirdropError>
```

### Provider Management
```rust
fn register_provider(
    env: Env, 
    admin: Address, 
    metric: Symbol, 
    provider: Address
) -> Result<(), AirdropError>

fn update_provider(
    env: Env, 
    admin: Address, 
    metric: Symbol, 
    new_provider: Address
) -> Result<(), AirdropError>

fn remove_provider(
    env: Env, 
    admin: Address, 
    metric: Symbol
) -> Result<(), AirdropError>
```

### Distribution Operations
```rust
fn claim_airdrop(env: Env, user: Address, event_id: u64) -> Result<(), AirdropError>

fn distribute_batch(
    env: Env,
    admin: Address,
    event_id: u64,
    users: Vec<Address>
) -> Result<(), AirdropError>
```

### Event Management
```rust
fn pause_event(env: Env, admin: Address, event_id: u64) -> Result<(), AirdropError>
fn resume_event(env: Env, admin: Address, event_id: u64) -> Result<(), AirdropError>
fn finalize_event(env: Env, admin: Address, event_id: u64) -> Result<(), AirdropError>
```

### Query Operations
```rust
fn get_event(env: Env, event_id: u64) -> Result<AirdropEvent, AirdropError>
fn get_event_stats(env: Env, event_id: u64) -> Result<EventStats, AirdropError>
fn list_claimed_users(env: Env, event_id: u64, max_results: u32) -> Result<Vec<Address>, AirdropError>
fn get_provider(env: Env, metric: Symbol) -> Result<Address, AirdropError>
```

## 🏗 Contract Structure

```
airdrop-contract/
├── src/
│   ├── lib.rs           # Contract entry points
│   ├── distribution.rs  # Distribution logic
│   ├── eligibility.rs   # Eligibility verification
│   ├── external.rs      # External provider integration
│   ├── tracking.rs      # Event and user tracking
│   ├── types.rs         # Data structures
│   └── test.rs          # Test suite
└── Cargo.toml
```

## 🔄 Airdrop Flow

1. **Event Creation**
   - Define airdrop parameters
   - Set eligibility conditions
   - Configure time constraints
   - Set distribution limits

2. **Eligibility Verification**
   - Check user conditions
   - Validate external metrics
   - Verify event status
   - Confirm claim eligibility

3. **Token Distribution**
   - Individual user claims
   - Batch distributions
   - Automatic token transfers
   - Event statistics updates

4. **Event Management**
   - Monitor distribution progress
   - Pause/resume as needed
   - Finalize completed events
   - Generate reports

## 🔐 Security Considerations

- **Admin Authorization**: All admin operations require authentication
- **Eligibility Validation**: Comprehensive eligibility checks
- **Duplicate Prevention**: Users cannot claim multiple times
- **Event Controls**: Pause/resume mechanisms for emergencies
- **Provider Security**: Secure external provider integration
- **Cap Enforcement**: Strict adherence to distribution limits

## 📊 Event Configuration

### Required Parameters
- **Name**: Human-readable event identifier
- **Description**: Detailed event description
- **Conditions**: Map of eligibility requirements
- **Amount**: Tokens per eligible user
- **Token Address**: Distribution token contract
- **Time Window**: Start and end timestamps

### Optional Parameters
- **Max Users**: Maximum number of participants
- **Max Total Amount**: Maximum total token distribution
- **Provider Registry**: External data source configuration

## 🚫 Error Handling

| Error | Code | Description |
|-------|------|-------------|
| AlreadyInitialized | 1 | Contract already initialized |
| Unauthorized | 2 | Insufficient permissions |
| InvalidTokenConfig | 3 | Invalid token configuration |
| AirdropNotFound | 4 | Event doesn't exist |
| UserNotEligible | 5 | User doesn't meet requirements |
| AlreadyClaimed | 6 | User already claimed tokens |
| InsufficientContractBalance | 7 | Contract lacks funds |
| TokenTransferFailed | 8 | Token transfer failed |
| ConditionNotFound | 9 | Eligibility condition not found |
| InvalidAmount | 10 | Invalid token amount |
| ProviderNotConfigured | 11 | Metric provider not set |
| ProviderCallFailed | 12 | External provider error |
| EventInactive | 13 | Event paused or ended |
| CapExceeded | 14 | Distribution limit reached |
| InvalidEventConfig | 15 | Invalid event parameters |

## 📈 Analytics & Tracking

- **Event Statistics**: Real-time distribution metrics
- **User Tracking**: Complete claim history
- **Provider Metrics**: External data source performance
- **Distribution Reports**: Comprehensive event reports

## 🧪 Testing

Run the test suite:
```bash
make test
```

## 🎯 Use Cases

- **Loyalty Rewards**: Reward long-term users
- **Community Incentives**: Bootstrap community engagement
- **Marketing Campaigns**: Token-based marketing initiatives
- **Product Launches**: Promote new product releases
- **Governance Tokens**: Distribute voting tokens
- **Referral Rewards**: Incentivize user referrals 