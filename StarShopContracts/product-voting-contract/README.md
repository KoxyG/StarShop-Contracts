# Product Voting Smart Contract

A Soroban smart contract implementing a comprehensive product voting system with ranking calculations, vote limits, and trend analysis.

## 🌟 Features

### Voting System
- **Upvote/Downvote Support**: Users can cast positive or negative votes on products
- **Vote Reversal Protection**: Limited time window for vote changes
- **Duplicate Vote Prevention**: Each user can only vote once per product
- **Vote History Tracking**: Complete audit trail of all votes

### Rate Limiting
- **Daily Vote Limits**: Prevents spam voting with configurable daily caps
- **Account Age Requirements**: New accounts must wait before voting
- **Time-Based Restrictions**: Voting period enforcement

### Ranking & Analytics
- **Real-Time Scoring**: Dynamic product score calculation
- **Trending Products**: Algorithmic trending product identification
- **Vote Weight System**: Sophisticated vote weighting mechanisms
- **Performance Metrics**: Comprehensive voting analytics

### Security Features
- **Anti-Gaming Measures**: Protection against vote manipulation
- **Account Verification**: Age and activity requirements
- **Limit Enforcement**: Multiple layers of rate limiting
- **Audit Trail**: Complete vote history tracking

## 📋 Prerequisites

- Rust toolchain
- Soroban CLI

## 🛠 Setup

Install dependencies:
```bash
make build
```

## 📝 Contract Interface

### Initialization
```rust
fn init(env: Env)
```

### Product Management
```rust
fn create_product(env: Env, id: Symbol, name: Symbol) -> Result<(), Error>
```

### Voting Operations
```rust
fn cast_vote(
    env: Env, 
    product_id: Symbol, 
    vote_type: VoteType, 
    voter: Address
) -> Result<(), Error>
```

### Query Operations
```rust
fn get_product_score(env: Env, product_id: Symbol) -> i32
fn get_trending_products(env: Env) -> Vec<Symbol>
```

## 🏗 Contract Structure

```
product-voting-contract/
├── src/
│   ├── lib.rs           # Contract entry points
│   ├── vote.rs          # Vote management logic
│   ├── ranking.rs       # Ranking calculations
│   ├── limits.rs        # Rate limiting & restrictions
│   ├── types.rs         # Data structures
│   └── test.rs          # Test suite
└── Cargo.toml
```

## 🔄 User Flow

1. **Product Creation**
   - Create products with unique identifiers
   - Set product metadata and descriptions

2. **Vote Casting**
   - Check user eligibility and limits
   - Cast upvote or downvote
   - Update product rankings automatically

3. **Trend Analysis**
   - Real-time score calculations
   - Trending product identification
   - Analytics and metrics

## 🔐 Security Considerations

- **Rate Limiting**: Daily vote limits prevent abuse
- **Account Age**: New accounts must wait before voting
- **Vote Validation**: Comprehensive input validation
- **Duplicate Prevention**: One vote per user per product
- **Audit Trail**: Complete vote history tracking

## 📊 Vote Types

| Type | Value | Description |
|------|-------|-------------|
| Upvote | 1 | Positive vote for product |
| Downvote | 2 | Negative vote for product |

## 🚫 Error Handling

| Error | Code | Description |
|-------|------|-------------|
| VotingPeriodEnded | 1 | Voting time window expired |
| AlreadyVoted | 2 | User already voted on this product |
| ReversalWindowExpired | 3 | Cannot change vote after window |
| DailyLimitReached | 4 | User exceeded daily vote limit |
| AccountTooNew | 5 | Account doesn't meet age requirements |
| ProductNotFound | 6 | Product doesn't exist |
| ProductExists | 7 | Product ID already taken |

## 🧪 Testing

Run the test suite:
```bash
make test
```

## 🎯 Use Cases

- **Product Discovery**: Help users find trending products
- **Community Feedback**: Gather user opinions on products
- **Market Research**: Analyze product popularity trends
- **Quality Control**: Democratic product quality assessment

## 📖 Overview
The **Product Voting Contract** is a smart contract built using Rust and the Soroban SDK. It enables users to create products and vote on them positively or negatively. The contract features a ranking system that considers both votes and product recency while implementing anti-spam measures and voting limits to maintain system integrity.

## 🚀 Features

### 1️⃣ Product Management
- Create new products with unique IDs and names.
- Verification system to prevent duplicate products.
- Voting period limited to **30 days** per product.

### 2️⃣ Voting System
- Users can upvote or downvote products.
- Daily voting limit of **10 votes per user**.
- Users must have an account older than **7 days** to vote.
- **24-hour window** to modify votes after casting.

### 3️⃣ Ranking System
- Scores are calculated based on positive and negative votes.
- Product ranking decays over time to ensure relevance.
- Trending products are determined based on **48-hour activity**.
- Function to retrieve trending products.

### 4️⃣ Security Measures
- New account restrictions to prevent spam.
- Daily voting limits to mitigate abuse.
- Prevention of duplicate votes.
- Voting period constraints to ensure fair play.


## Contract Structure

The contract is organized into several modules:

```
src/
├── lib.rs         # Main contract implementation
├── vote.rs        # Vote management logic
├── ranking.rs     # Ranking calculation system
├── limits.rs      # Voting limits implementation
└── types.rs       # Data structures and types
```

## 🛠 Installation & Deployment

Ensure you have **Rust** and **Soroban CLI** installed.

### Compile the Contract
```bash
cargo build --target wasm32-unknown-unknown --release
```

---

## ⚡ Usage Examples

### Initialize the Contract
```rust
use soroban_sdk::{Env, Symbol, Address};
use product_voting::{ProductVoting, ProductVotingTrait, VoteType};

// Create a test environment
let env = Env::default();
let contract_id = env.register_contract(None, ProductVoting);
let client = ProductVotingClient::new(&env, &contract_id);

// Initialize the contract
client.init();
```

### Create a New Product
```rust
let product1_id = Symbol::short("PROD1");
let product1_name = Symbol::short("First Product");
client.create_product(&product1_id, &product1_name)
    .expect("Failed to create product");
```

### Cast a Vote
```rust
// Generate a voter address
let voter = Address::generate(&env);

// Cast an upvote
client.cast_vote(&product1_id, VoteType::Upvote, &voter)
    .expect("Failed to cast vote");
```

### Retrieve Product Score
```rust
// Get individual product score
let score = client.get_product_score(&product1_id);
```

### Fetch Trending Products
```rust
// Get list of trending products
let trending_products = client.get_trending_products();
```

### Compilation in local

To compile the contract, follow these steps:

```sh
stellar contract build
```

### Run the test

```bash
cargo test  
```
Output
```bash
running 1 test
test test::test ... ok 
```




## 📚 References
- [Soroban Official Guide](https://soroban.stellar.org/docs/)
- [Rust Programming Language](https://doc.rust-lang.org/book/)

---

### ✨ Contribution
Contributions are welcome! Feel free to open an issue or submit a pull request to improve the contract or documentation.

🚀 Happy coding! 🎉

