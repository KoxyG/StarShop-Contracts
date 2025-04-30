use soroban_sdk::{token, Address, Env};

// Transfer tokens from contract
pub fn transfer_from_contract(env: &Env, token: &Address, to: &Address, amount: &i128) {
    token::Client::new(env, token).transfer(&env.current_contract_address(), to, amount);
}

// Transfer tokens to contract
pub fn transfer_to_contract(env: &Env, token: &Address, from: &Address, amount: &i128) {
    token::Client::new(env, token).transfer(from, &env.current_contract_address(), amount);
}
