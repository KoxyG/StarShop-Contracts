# Contents
 1. [Prerequisites](#prerequisites) 

 2. [Environment Setup](#environment-setup) 
    - Configuring Stellar Smart Contracts
    - Specific steps to install related tools or plugins

 3. [Wallet Configuration](#wallet-configuration)
    - Instructions to connect and configure the wallet

 4. [Compilation and Deployment](#compilation-and-deployment)

 5. [Testing and Execution](#testing-and-execution)

 6. [Troubleshooting](#troubleshooting)
    - Tips and solutions for common errors during the setup process.

## Prerequisites
To build and develop contracts you need some prerequisites:
- A [Rust](https://www.rust-lang.org/) toolchain
- A Code Editor
- [Stellar CLI](https://developers.stellar.org/docs/build/smart-contracts/getting-started/setup#install-the-stellar-cli)
- Install Cargo (Rust's package manager)

## Environment Setup
[macOS/Linux](#macOS/linus) |  [Windows](#windows-rust-installation)  

### macOS/Linux Rust Installation
```
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```
Install the target: Install the `wasm32-unknown-unknown` target.
```
rustup target add wasm32-unknown-unknown
```

### macOS/Linux Code Editor Configuration
Many editors support Rust. For more on how to configure your editor: https://www.rust-lang.org/tools

- [Visual Studio Code](https://code.visualstudio.com/) editor (A very popular code editor)
- [Rust Analyzer](https://marketplace.visualstudio.com/items?itemName=rust-lang.rust-analyzer) for Rust language support 
- [CodeLLDB](https://marketplace.visualstudio.com/items?itemName=vadimcn.vscode-lldb) for step-through-debugging


### macOS/Linux Stellar CLI Installation
There are a few ways to install the [latest release](https://github.com/stellar/stellar-cli/releases) of Stellar CLI.

Install with Homebrew (macOS, Linux)

For steps to [install Homebrew](https://brew.sh/) on macOS/Linux

```
brew install stellar-cli
```

Install with cargo from source:

For steps to [install cargo](https://doc.rust-lang.org/cargo/getting-started/installation.html) on macOS/Linux

```
cargo install --locked stellar-cli@22.0.1 --features opt
```
Autocompletion for macOS/Linux: You can use `stellar completion` to generate shell completion for different shells.

[Bash](#bash) |  [ZSH](#zsh)  |   [Fish](#fish) |   [PowerShell](#powershell) |   [Elvish](#elvish)

### Bash
To enable autocomplete on the current shell session:

```
echo "source <(stellar completion --shell bash)" >> ~/.bashrc
```

To enable autocomplete permanently, run the following command, then restart your terminal:

```
echo "source <(stellar completion --shell bash)" >> ~/.bashrc
```

### ZSH
To enable autocomplete on the current shell session:

```
source <(stellar completion --shell zsh)
```

To enable autocomplete permanently, run the following commands, then restart your terminal:

```
echo "source <(stellar completion --shell zsh)" >> ~/.zshrc
```

### Fish
To enable autocomplete on the current shell session:

```
stellar completion --shell fish | source
```

To enable autocomplete permanently, run the following command, then restart your terminal:

```
echo "stellar completion --shell fish | source" >> ~/.config/fish/config.fish
```

### PowerShell
To enable autocomplete on the current shell session:

```
stellar completion --shell powershell | Out-String | Invoke-Expression
```

To enable autocomplete permanently, run the following commands, then restart your terminal:

```
New-Item -ItemType Directory -Path $(Split-Path $PROFILE) -Force
if (-Not (Test-Path $PROFILE)) { New-Item -ItemType File -Path $PROFILE | Out-Null }
Add-Content $PROFILE 'Set-PSReadlineKeyHandler -Key Tab -Function MenuComplete'
Add-Content $PROFILE 'stellar completion --shell powershell | Out-String | Invoke-Expression'
```

### Elvish
To enable autocomplete on the current shell session:

```
source (stellar completion --shell elvish)
```

To enable autocomplete permanently, run the following commands, then restart your terminal:

```
echo "source (stellar completion --shell elvish)" >> ~/.elvish/rc.elv
```

#### Windows Rust Installation
On Windows, download and run [rustup-init.exe](https://static.rust-lang.org/rustup/dist/i686-pc-windows-gnu/rustup-init.exe). You can continue with the default settings by pressing Enter.

NOTE: It is recommended to use the Windows Terminal. See how to install [Windows Terminal ](https://learn.microsoft.com/en-us/windows/terminal/install)

For WSL users, follow the same instructions as Linux users

Install the target: Install the `wasm32-unknown-unknown` target.
```
rustup target add wasm32-unknown-unknown
```

#### Windows Code Editor Configuration
Many editors have support for Rust. Visit the following link to find out how to configure your editor:
https://www.rust-lang.org/tools

- [Visual Studio Code](https://code.visualstudio.com/) editor (A very popular code editor)
- [Rust Analyzer](https://marketplace.visualstudio.com/items?itemName=rust-lang.rust-analyzer) for Rust language support 
- [CodeLLDB](https://marketplace.visualstudio.com/items?itemName=vadimcn.vscode-lldb) for step-through-debugging

#### Windows Stellar CLI Installation
There are a three ways to install the [latest release](https://github.com/stellar/stellar-cli/releases) of Stellar CLI.

Using the installer:

1. Download the installer from the [latest release](Download the installer from the latest release.).
2. Go to your Downloads folder, double click the installer and follow the wizard instructions.
3. Restart your terminal to use the `stellar` command.


Using [winget](https://learn.microsoft.com/en-us/windows/package-manager/winget/):
```
winget install --id Stellar.StellarCLI --version 22.0.1
```

Install with cargo from source:
```
cargo install --locked stellar-cli@22.0.1 --features opt
```

#### Autocompletion
You can use `stellar completion `to generate shell completion for different shells. 

[Bash](#bash-for-windows) |  [ZSH](#zsh-for-windows)  |   [Fish](#fish-for-windows) |   [PowerShell](#powershell) |   [Elvish](#elvish)

### Bash for indows
To enable autocomplete on the current shell session:
```
source <(stellar completion --shell bash)
```

To enable autocomplete permanently, run the following command, then restart your terminal:
```
echo "source <(stellar completion --shell bash)" >> ~/.bashrc
```

### ZSH for windows
To enable autocomplete on the current shell session:
```
source <(stellar completion --shell zsh)
```

To enable autocomplete permanently, run the following commands, then restart your terminal:
```
echo "source <(stellar completion --shell zsh)" >> ~/.zshrc
```

### ZSH for fish
To enable autocomplete on the current shell session:
```
stellar completion --shell fish | source
```

To enable autocomplete permanently, run the following command, then restart your terminal:
```
echo "stellar completion --shell fish | source" >> ~/.config/fish/config.fish
```


















## Wallet Configuration
1. Configure an identity (e.g., "alice")
```
stellar keys generate --global alice --network testnet --fund

```

2. This command creates a new account on the testnet with some initial funds
```
stellar keys address alice
```



## Compilation and Deployment
Create a New Project: `soroban-hello-world` project
```
stellar contract init soroban-hello-world
```

This creates Rust workspace project with a folder structure:
```
.
├── Cargo.lock
├── Cargo.toml
├── README.md
└── contracts
    └── hello_world
        ├── Cargo.toml
        └── src
            ├── lib.rs
            └── test.rs

```

`Cargo.toml`: The `Cargo.toml` file in the root directory is setup as the Rust Workspace. Here we can put multiply smart contracts in one project.

Rust Workspace:
The `Cargo.toml` file defines the workspace's members as all contents of the contracts directory and specifies the soroban-sdk dependency version, including the testutils feature, to enable test utilities for contract testing.

```
[workspace]
resolver = "2"
members = [
  "contracts/*",
]

[workspace.dependencies]
soroban-sdk = "20.3.2"
```

`release` Profile: 
Optimizing the release profile is essential for building Soroban contracts, as they must not exceed the 64KB size limit. Without these configurations, Rust programs typically surpass this limit.

The Cargo.toml file release profile configuration:
```
[profile.release]
opt-level = "z"
overflow-checks = true
debug = 0
strip = "symbols"
debug-assertions = false
panic = "abort"
codegen-units = 1
lto = true
```

`release-with-logs` Profile:
A release-with-logs profile is useful for building a .wasm file with logging enabled for debug logs via stellar-cli. It's unnecessary for accessing debug logs in tests or using a debugger.

```
[profile.release-with-logs]
inherits = "release"
debug-assertions = true
```

Contracts Directory: 
The contracts directory contains Soroban contracts, each in its own folder, including a hello_world contract as a starter.

Contract-specific Cargo.toml file:
Every contract should have its own `Cargo.toml` file, which relies on the top-level Cargo.toml that we just discussed.

This is where we can specify contract-specific package information.
```
[package]
name = "hello-world"
version = "0.0.0"
edition = "2021"
publish = false
```

The `crate-type` is configured to `cdylib` which is required for building contracts.
```
[lib]
crate-type = ["cdylib"]
doctest = false
```

We also have included the soroban-sdk dependency, configured to use the version from the workspace Cargo.toml.
```
[dependencies]
soroban-sdk = { workspace = true }

[dev-dependencies]
soroban-sdk = { workspace = true, features = ["testutils"] }
```

Contract Source Code:
To create a Soroban contract, write Rust code in the `lib.rs` file, starting with `#![no_std]` to exclude the standard library, as it's too large for blockchain deployments.
```
#![no_std]
```

The contract imports the types and macros that it needs from the soroban-sdk crate.
```
use soroban_sdk::{contract, contractimpl, symbol_short, vec, Env, Symbol, Vec};
```

Soroban contracts lack standard Rust types like std::vec::Vec due to no allocator or heap memory. Instead, the soroban-sdk offers types like Vec, Map, Bytes, BytesN, and Symbol, optimized for Soroban's environment. Primitive types like u128, i128, u64, and bool are supported, but floats and floating-point math are not.

Contract inputs must not be references.

The `#[contract]` attribute marks the Contract struct as the type for implementing contract functions.
```
#[contract]
pub struct HelloContract;
```

Contract functions are defined in an `impl` block annotated with `#[contractimpl]`. Function names must be 32 characters or fewer, and externally callable functions should be marked pub. The first argument is often of type `Env`, providing access to the Soroban environment for contract operations.
```
#[contractimpl]
impl HelloContract {
    pub fn hello(env: Env, to: Symbol) -> Vec<Symbol> {
        vec![&env, symbol_short!("Hello"), to]
    }
}
```

Putting those pieces together a simple contract looks like this.

```
#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, vec, Env, Symbol, Vec};

#[contract]
pub struct HelloContract;

#[contractimpl]
impl HelloContract {
    pub fn hello(env: Env, to: Symbol) -> Vec<Symbol> {
        vec![&env, symbol_short!("Hello"), to]
    }
}

mod test;
```

Note the `mod test `line at the bottom, this will tell Rust to compile and run the test code, which we’ll take a look at next.

### Deployment to Testnet
[Deployment on macOS/Linux](#deployment-using-macos/linux) | [Deploy on Windows (powershell)](#deployment-using-windows)

### Deployment using macOS/Linux
```
stellar contract deploy \
  --wasm target/wasm32-unknown-unknown/release/hello_world.wasm \
  --source alice \
  --network testnet
```

This returns the contract's id, starting with a C. In this example, we're going to use
`CACDYF3CYMJEJTIVFESQYZTN67GO2R5D5IUABTCUG3HXQSRXCSOROBAN`, so replace it with your actual contract id.

### Interact:

Using the code we wrote in Write a Contract and the resulting .wasm file we built in Build, run the following command to invoke the `hello` function.
```
stellar contract invoke \
  --id CACDYF3CYMJEJTIVFESQYZTN67GO2R5D5IUABTCUG3HXQSRXCSOROBAN \
  --source alice \
  --network testnet \
  -- \
  hello \
  --to RPC
  ```

  Output
  ```
  ["Hello", "RPC"]
  ```


### Deployment using Windows 
```
stellar contract deploy `
  --wasm target/wasm32-unknown-unknown/release/hello_world.wasm `
  --source alice `
  --network testnet

```
This returns the contract's id, starting with a C. In this example, we're going to use `CACDYF3CYMJEJTIVFESQYZTN67GO2R5D5IUABTCUG3HXQSRXCSOROBAN`, so replace it with your actual contract id.


### Interact
Using the code we wrote in Write a Contract and the resulting .wasm file we built in Build, run the following command to invoke the `hello` function.

```
stellar contract invoke `
  --id CACDYF3CYMJEJTIVFESQYZTN67GO2R5D5IUABTCUG3HXQSRXCSOROBAN `
  --source alice `
  --network testnet `
  -- `
  hello `
  --to RPC

```

Output:
```
["Hello", "RPC"]
```


## Testing and Execution
Writing tests for Soroban contracts involves writing Rust code using the test facilities and toolchain that you'd use for testing any Rust code.

Given our HelloContract, a simple test will look like this.
```
#![cfg(test)]

use super::*;
use soroban_sdk::{symbol_short, vec, Env};

#[test]
fn test() {
    let env = Env::default();
    let contract_id = env.register_contract(None, HelloContract);
    let client = HelloContractClient::new(&env, &contract_id);

    let words = client.hello(&symbol_short!("Dev"));
    assert_eq!(
        words,
        vec![&env, symbol_short!("Hello"), symbol_short!("Dev"),]
    );
}
```

In any test the first thing that is always required is an Env, which is the Soroban environment that the contract will run inside of.
```
let env = Env::default();
```

The contract is registered with the environment using its type. A fixed contract ID can be specified, or None can be provided to auto-generate one.
```
let contract_id = env.register_contract(None, Contract);
```

Public functions in an impl block with the #[contractimpl] attribute are mirrored in a generated client type. The client type's name is the contract type's name with "Client" appended (e.g., HelloContract has a client named HelloContractClient).
```
let client = HelloContractClient::new(&env, &contract_id);
let words = client.hello(&symbol_short!("Dev"));
```

The values returned by functions can be asserted on:
```
assert_eq!(
    words,
    vec![&env, symbol_short!("Hello"), symbol_short!("Dev"),]
);
```

Run the Tests:
Run cargo test 
```
cargo test
```
Output
```
running 1 test
test test::test ... ok
```


Build the contract
```
stellar contract build
```

Optimizing Builds
```
cargo install --locked stellar-cli --features opt
```

Then build an optimized .wasm file:
```
stellar contract optimize --wasm target/wasm32-unknown-unknown/release/hello_world.wasm
```
This will optimize and output a new hello_world.optimized.wasm file in the same location as the input .wasm.


## Troubleshooting
1. If you encounter an XDR error during deployment, try these steps:
- Ensure your account has sufficient funds
- Double-check the WASM hash
- Verify network connectivity

2. Common errors often relate to incorrect syntax or missing dependencies. Always check the Stellar documentation and community forums for the most up-to-date solutions.

3. If you're having trouble connecting to the testnet, ensure your CLI is properly configured:
```
stellar network add \
--global testnet \
--rpc-url https://soroban-testnet.stellar.org:443 \
--network-passphrase "Test SDF Network ; September 2015"
```
4. When you build a contract and get an error like `can't find crate for 'core'` it means you didn't install the wasm32 target during the setup step. You can do it so by running `rustup target add wasm32-unknown-unknown`.

