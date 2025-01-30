# Product Voting Contract

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

## 📚 References
- [Soroban Official Guide](https://soroban.stellar.org/docs/)
- [Rust Programming Language](https://doc.rust-lang.org/book/)

---

### ✨ Contribution
Contributions are welcome! Feel free to open an issue or submit a pull request to improve the contract or documentation.

🚀 Happy coding! 🎉

