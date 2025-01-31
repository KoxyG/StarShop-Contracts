# 🎮 NFT Contract on Stellar (Soroban SDK)

## 🎯 Objective

This document provides comprehensive details about the NFT contract, including its purpose, setup, usage, and interaction within the **Stellar Soroban SDK**.

## 📌 Overview

This smart contract facilitates:

- **Minting NFTs** with metadata (name, description, attributes) and assigning unique IDs.
- **Updating metadata** to modify NFT attributes and descriptions.
- **Transferring NFT ownership** securely between users.
- **Burning NFTs** to remove them from the blockchain.
- **Admin functionality** to control metadata updates and contract management.
- **Querying NFT data** to retrieve ownership and metadata details.
- **Tracking NFT transactions** to log and monitor ownership history.

## 🏗 Contract Structure

| File              | Description                                                                             |
| ----------------- | --------------------------------------------------------------------------------------- |
| `lib.rs`          | Defines the contract structure, manages initialization, and enforces admin permissions. |
| `minting.rs`      | Implements the `mint_nft` function to create new NFTs and store metadata.               |
| `metadata.rs`     | Handles metadata updates, ensuring only admins can modify NFT attributes.               |
| `distribution.rs` | Implements `transfer_nft` and `burn_nft` for ownership transfers and NFT deletion.      |
| `query.rs`        | Allows users to fetch NFT details, including metadata and ownership.                    |
| `history.rs`      | Records transaction logs for tracking NFT ownership changes.                            |
| `test.rs`         | Contains unit tests to validate contract functionality.                                 |

## ⚙️ Setup & Deployment

### 📦 Prerequisites

- Rust and Cargo installed.
- Stellar CLI installed (`cargo install stellar-cli`).
- Stellar testnet account with funds.

### 🖥️ Environment Setup

Follow the environment setup instructions from the [Stellar Official Guide](https://soroban.stellar.org/), including Rust toolchain installation, editor configuration, and CLI setup.

### 🔗 Compilation

To compile the contract, follow these steps:

```sh
stellar contract build
```

### For optimized builds:

```sh
stellar contract optimize --wasm target/wasm32-unknown-unknown/release/implement-nft-contract.wasm
```

### 🚀 Deployment  
Refer to the official Stellar CLI documentation for detailed deployment instructions. Ensure that:  

- The contract is properly compiled.  
- A valid testnet account is configured.  
- The contract is deployed and registered using:  

```sh
stellar contract deploy
```


### 🔑 Key Functions  

#### 1️⃣ Minting an NFT  

```rust
pub fn mint_nft(env: Env, to: Address, name: String, description: String, attributes: Vec<String>) -> u32
```

- **Auth Required:** Owner (`to`).  
- **Functionality:** Creates a new NFT, assigns it a unique ID, and stores metadata.  
- **Returns:** `token_id` (Unique identifier of the NFT).  

#### 2️⃣ Updating NFT Metadata  

```rust
pub fn update_metadata(env: Env, admin: Address, token_id: u32, name: String, description: String, attributes: Vec<String>)
```

- **Auth Required:** Admin.  
- **Functionality:** Allows the admin to update the name, description, and attributes of an NFT.  
- **Ensures:** Only authorized admins can modify metadata.  

#### 3️⃣ Transferring an NFT  

```rust
pub fn transfer_nft(env: Env, from: Address, to: Address, token_id: u32)
```

- **Auth Required:** Current owner (`from`).  
- **Functionality:** Transfers ownership of the NFT to another address.  
- **Ensures:** The sender is the valid owner before processing the transfer.  

#### 4️⃣ Burning an NFT  

```rust
pub fn burn_nft(env: Env, owner: Address, token_id: u32)
```

- **Auth Required:** Owner.  
- **Functionality:** Permanently deletes an NFT from storage.  
- **Ensures:** Only the NFT owner can initiate burning.  

#### 5️⃣ Querying NFT Details  

```rust
pub fn get_nft_data(env: Env, token_id: u32) -> NFTMetadata
```

- **Auth Required:** None.  
- **Functionality:** Retrieves metadata and ownership details of an NFT.  
- **Returns:** `NFTMetadata` containing name, description, attributes, and owner.  

#### 6️⃣ Tracking NFT Transactions  

```rust
pub fn get_nft_history(env: Env, token_id: u32) -> Vec<TransactionRecord>
```

- **Auth Required:** None.  
- **Functionality:** Fetches a history of ownership changes for a specific NFT.  
- **Returns:** A list of `TransactionRecord` containing previous owners and timestamps.  

### 📂 References  

- [Stellar Official Guide](https://soroban.stellar.org/)  
- [Rust Book](https://doc.rust-lang.org/book/)  
- [Soroban SDK Documentation](https://soroban.stellar.org/docs/)  
- [Stellar Developers Documentation](https://developers.stellar.org/docs/)  
- [Cargo - Rust Package Manager](https://doc.rust-lang.org/cargo/)  

### 🔍 Additional Considerations  

- **Access Control:**  
  - Only the admin (set in `initialize`) can update metadata.  
  - Owners must authorize transfers and burns.  

- **Error Handling:**  
  - Functions check if an NFT exists before modifying or retrieving it.  
  - Unauthorized actions trigger a panic (`Unauthorized`).  

- **Storage Optimization:**  
  - NFT data is stored persistently using `env.storage().persistent()`.  
  - The counter for new NFTs is only updated when minting.  

- **Testing Notes:**  
  - Ensure correct admin setup during initialization.  
  - Test unauthorized actions to confirm security.  
  - Verify that transfers and burns update storage correctly.  

🚀 **Test on Stellar Testnet before mainnet deployment!**
