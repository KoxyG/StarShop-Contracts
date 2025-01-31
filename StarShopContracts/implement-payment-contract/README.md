# Payment Contract

## Overview

The **Payment Contract** is a Soroban smart contract designed to handle financial transactions securely while providing robust administrative controls, dispute resolution, and refund mechanisms. This contract ensures that all transactions adhere to security protocols and prevents unauthorized access or fraudulent activity.

This contract is modular and consists of four primary components:

- **PaymentContract**: Responsible for contract initialization, upgrades, and administrative control.
- **TransactionContract**: Manages deposits and transfers between users.
- **RefundContract**: Provides a mechanism for issuing refunds securely.
- **DisputeContract**: Resolves conflicts between parties via an arbitrator.

## Features

- **Secure Fund Transfers**: Ensures only authorized entities can perform financial operations.
- **Admin Control**: Enables contract upgrades and allows admin privileges to be transferred securely.
- **Dispute Resolution**: Implements arbitration logic to fairly resolve disputes.
- **Refund Management**: Facilitates the reversal of transactions when necessary.
- **Event Emission**: Logs significant contract interactions for transparency.

## Contract Functions

### Payment Contract

#### `initialize(env: Env, admin: Address) -> Result<(), PaymentError>`

Initializes the contract and assigns an admin address. Ensures the contract is only initialized once.

#### `upgrade(env: Env, new_wasm_hash: BytesN<32>) -> Result<(), PaymentError>`

Allows the contract administrator to deploy an upgraded version of the contract.

#### `get_admin(env: Env) -> Result<Address, PaymentError>`

Retrieves the current admin’s address.

#### `transfer_admin(env: Env, new_admin: Address) -> Result<(), PaymentError>`

Transfers contract administrative control to another address after authentication.

### Transaction Contract

#### `process_deposit(env: Env, token_id: Address, signer: Address, to: Address, amount: i128) -> Result<(), TransactionError>`

Handles deposits by transferring tokens from a signer to a designated recipient.

### Refund Contract

#### `process_refund(env: Env, token_id: Address, signer: Address, to: Address, refund_amount: i128) -> Result<(), RefundError>`

Executes a refund process ensuring the sender has the necessary balance.

### Dispute Contract

#### `resolve_dispute(env: Env, token_id: Address, arbitrator: Address, buyer: Address, seller: Address, refund_amount: i128, decision: DisputeDecision) -> Result<(), DisputeError>`

Allows an arbitrator to make a binding decision in a financial dispute, either refunding the buyer or paying the seller.

## Setup and Deployment

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

## Error Handling

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
- **UnauthorizedAccess**: Unauthorized entity attempted to resolve a dispute.

## Conclusion

This contract ensures the integrity of financial transactions while allowing for controlled administrative functions and dispute resolution. By implementing robust security measures, the contract guarantees safe, transparent, and fair financial operations within the Soroban ecosystem.