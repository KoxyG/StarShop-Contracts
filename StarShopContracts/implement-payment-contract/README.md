# Payment Contract

## Overview

The **Payment Contract** is a smart contract designed to manage administrative control and upgrades for a transaction-based system. It serves as the foundation for handling payments, disputes, and refunds by allowing an administrator to initialize the contract, manage upgrades, and transfer ownership.

The contract integrates with other modules such as `DisputeContract`, `RefundContract`, and `TransactionContract`, which collectively form a robust payment system.
This contract is modular and consists of four primary components:

## Purpose

The **Payment Contract** is primarily responsible for:
- Initializing the contract and setting an administrator.
- Allowing the administrator to upgrade the contract with new WASM code.
- Providing a mechanism to retrieve the current administrator.
- Enabling the transfer of administrative rights to a new address.

## Features

- **Secure Fund Transfers**: Ensures only authorized entities can perform financial operations.
- **Admin Control**: Enables contract upgrades and allows admin privileges to be transferred securely.
- **Dispute Resolution**: Implements arbitration logic to fairly resolve disputes.
- **Refund Management**: Facilitates the reversal of transactions when necessary.
- **Event Emission**: Logs significant contract interactions for transparency.
- 

## Contract Functions

### 1. Initialization (`initialize`)
**Function Signature:**
```pub fn initialize(env: Env, admin: Address) -> Result<(), PaymentError>```
**Description:**
- This function initializes the contract by setting an administrator.
- It ensures that the contract is not already initialized.
- The `admin` address is required to authenticate itself before being stored as the contract administrator.
- Once set, an event (`init`) is published.

### 2. Upgrading Contract (`upgrade`)
**Function Signature:**
```pub fn upgrade(env: Env, new_wasm_hash: BytesN<32>) -> Result<(), PaymentError>```

**Description:**
- This function allows the admin to update the contract with new WASM code.
- The admin must authenticate before proceeding.
- After a successful upgrade, an event (`upgrade`) is published.

### 3. Retrieve Admin (`get_admin`)
**Function Signature:**
```pub fn get_admin(env: Env) -> Result<Address, PaymentError>```

**Description:**
- Retrieves the currently assigned administrator address.
- Returns an error if the contract is not initialized.

### 4. Transfer Admin Rights (`transfer_admin`)
**Function Signature:**
```pub fn transfer_admin(env: Env, new_admin: Address) -> Result<(), PaymentError>```

**Description:**
- Allows the current admin to transfer administrative rights to a new address.
- Both the current and new admin must authenticate before the transfer.
- Upon success, an event (`adm_xfer`) is published.

---

## Contract Structure
The contract is organizde into several modules: 

```
src/
├── lib.rs         # Main contract implementation
├── dispute.rs     # Handles transaction disputes and resolution logic
├── refund.rs      # Manages refund processing and conditions
├── transaction.rs # Implements payment processing and limits
```


## Installation and Deployment
Ensure you have **Rust** and **Soroban CLI** installed.

### Prerequisites

- Rust toolchain
- Soroban CLI
- Soroban SDK

### Build the Contract

```sh
cargo build --release --target wasm32-unknown-unknown
```

### Deploy the Contract

1. Install Soroban CLI:
   ```sh
   cargo install --git https://github.com/stellar/rs-soroban-cli soroban-cli
   ```
2. Deploy:
   ```sh
   soroban contract deploy --wasm target/wasm32-unknown-unknown/release/payment_contract.wasm
   ```
3. Initialize the contract:
   ```sh
   soroban contract invoke --id <contract_id> --fn initialize --args <admin_address>
   ```

## Interaction

### Call Functions

Using Soroban CLI, invoke contract functions:

```sh
soroban contract invoke --id <contract_id> --fn get_admin
```

<!-- ## Error Handling

### Payment Errors

- **NotInitialized**: The contract has not been initialized.
- **AlreadyInitialized**: The contract is already initialized and cannot be reinitialized.
- **UnauthorizedAccess**: The caller does not have the necessary permissions to perform the operation.

### Transaction Errors

- **InsufficientFunds**: The transaction initiator lacks the required balance.
- **TransferFailed**: The transfer operation was unsuccessful.
- **InvalidAmount**: The transaction amount is invalid (e.g., negative or zero).
- **UnauthorizedAccess**: Unauthorized entity attempted to initiate a transaction.

### Refund Errors

- **InsufficientFunds**: The sender lacks sufficient balance for the refund.
- **TransferFailed**: Refund transaction failed due to unforeseen errors.
- **InvalidAmount**: The refund amount must be a positive integer.
- **UnauthorizedAccess**: Unauthorized entity attempted a refund.

### Dispute Errors

- **InsufficientFunds**: The arbitrator does not have sufficient balance to execute a resolution.
- **TransferFailed**: Funds transfer failed while executing a dispute resolution.
- **InvalidAmount**: Refund amount in the dispute process is not valid.
- **UnauthorizedAccess**: Unauthorized entity attempted to resolve a dispute. -->

## References
- [Soroban Official Guide](https://soroban.stellar.org/docs/)
- [Rust Programming Language](https://doc.rust-lang.org/book/)

## Conclusion
The **Payment Contract** plays a crucial role in managing administrative privileges within the payment system. It ensures security by enforcing authentication on key actions like initialization, upgrades, and admin transfers. Properly setting up this contract is essential for the smooth operation of the overall payment platform.