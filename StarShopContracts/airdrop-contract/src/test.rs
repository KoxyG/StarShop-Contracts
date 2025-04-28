#![cfg(test)]

use super::{
    AirdropContract, AirdropContractClient,
    types::{AirdropError, AirdropEvent, DataKey, EventStats},
};
use soroban_sdk::{
    Address, Bytes, Env, Map, Symbol, Vec, contract, contractimpl, symbol_short,
    testutils::{Address as _, Events as _, Ledger as _},
    token::{StellarAssetClient as TokenAdmin, TokenClient},
};

// MetricProvider trait for testing
pub trait MetricProvider {
    fn get_user_metric(env: Env, user: Address, metric: Symbol) -> Result<u64, AirdropError>;
}

// ReferralContract for testing
#[contract]
pub struct ReferralContract;

#[contractimpl]
impl ReferralContract {
    pub fn initialize(env: Env, admin: Address) {
        admin.require_auth();
        env.storage().persistent().set(&DataKey::Admin, &admin);
    }

    pub fn record_referral(
        env: Env,
        admin: Address,
        referrer: Address,
        _referred: Address,
    ) -> Result<(), AirdropError> {
        admin.require_auth();
        if !env
            .storage()
            .persistent()
            .get::<_, Address>(&DataKey::Admin)
            .map(|a| a == admin)
            .unwrap_or(false)
        {
            return Err(AirdropError::Unauthorized);
        }
        let key = (referrer.clone(), Symbol::new(&env, "referrals"));
        let count: u64 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage().persistent().set(&key, &(count + 1));
        Ok(())
    }
}

#[contractimpl]
impl MetricProvider for ReferralContract {
    fn get_user_metric(env: Env, user: Address, metric: Symbol) -> Result<u64, AirdropError> {
        if metric != Symbol::new(&env, "referrals") {
            return Err(AirdropError::InvalidEventConfig);
        }
        let key = (user.clone(), metric.clone());
        Ok(env.storage().persistent().get(&key).unwrap_or(0))
    }
}

// SubscriptionContract for testing
#[contract]
pub struct SubscriptionContract;

#[contractimpl]
impl SubscriptionContract {
    pub fn initializesubs(env: Env, admin: Address) {
        admin.require_auth();
        env.storage().persistent().set(&DataKey::Admin, &admin);
    }

    pub fn subscribe(env: &Env, admin: Address, user: Address) -> Result<(), AirdropError> {
        admin.require_auth();
        if !env
            .storage()
            .persistent()
            .get::<_, Address>(&DataKey::Admin)
            .map(|a| a == admin)
            .unwrap_or(false)
        {
            return Err(AirdropError::Unauthorized);
        }
        let key = (user.clone(), Symbol::new(env, "subscription_start"));
        env.storage()
            .persistent()
            .set(&key, &env.ledger().timestamp());
        Ok(())
    }
}

#[contractimpl]
impl MetricProvider for SubscriptionContract {
    fn get_user_metric(env: Env, user: Address, metric: Symbol) -> Result<u64, AirdropError> {
        if *metric != Symbol::new(env, "subscription_days") {
            return Err(AirdropError::InvalidEventConfig);
        }
        let key = (user.clone(), Symbol::new(env, "subscription_start"));
        let start_time: u64 = env.storage().persistent().get(&key).unwrap_or(0);
        if start_time == 0 {
            return Ok(0);
        }
        let days = (env.ledger().timestamp() - start_time) / (24 * 60 * 60);
        Ok(days)
    }
}

// LoyaltyContract for testing
#[contract]
pub struct LoyaltyContract;

#[contractimpl]
impl LoyaltyContract {
    pub fn initialize(env: Env, admin: Address) {
        admin.require_auth();
        env.storage().persistent().set(&DataKey::Admin, &admin);
    }

    pub fn add_points(
        &self,
        env: &Env,
        admin: Address,
        user: Address,
        points: u64,
    ) -> Result<(), AirdropError> {
        admin.require_auth();
        if !env
            .storage()
            .persistent()
            .get::<_, Address>(&DataKey::Admin)
            .map(|a| a == admin)
            .unwrap_or(false)
        {
            return Err(AirdropError::Unauthorized);
        }
        let key = (user.clone(), Symbol::new(env, "loyalty_points"));
        let current: u64 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage().persistent().set(&key, &(current + points));
        Ok(())
    }
}

#[contractimpl]
impl MetricProvider for LoyaltyContract {
    fn get_user_metric(
        &self,
        env: &Env,
        user: &Address,
        metric: &Symbol,
    ) -> Result<u64, AirdropError> {
        if *metric != Symbol::new(env, "loyalty_points") {
            return Err(AirdropError::InvalidEventConfig);
        }
        let key = (user.clone(), metric.clone());
        Ok(env.storage().persistent().get(&key).unwrap_or(0))
    }
}

fn create_test_env() -> (Env, Address, AirdropContractClient) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, AirdropContract);
    let client = AirdropContractClient::new(&env, &contract_id);
    (env, contract_id, client)
}

fn setup_token(env: &Env) -> (Address, TokenAdmin) {
    let token_admin = Address::generate(env);
    let token = env.register_stellar_asset_contract_v2(token_admin.clone());
    (token.address(), TokenAdmin::new(env, &token.address()))
}

fn create_airdrop_event(
    client: &AirdropContractClient,
    admin: &Address,
    conditions: Map<Symbol, u64>,
    amount: u64,
    token_address: &Address,
) -> u64 {
    let name = Symbol::new(&client.env(), "Airdrop1");
    let description = Bytes::from_slice(&client.env(), b"Test airdrop");
    let start_time = client.env().ledger().timestamp();
    let end_time = start_time + 1000;
    client.trigger_airdrop(
        admin,
        &name,
        &description,
        &conditions,
        &amount,
        token_address,
        &start_time,
        &end_time,
        &None,
        &None,
    );
    client
        .env()
        .storage()
        .persistent()
        .get(&DataKey::EventId)
        .unwrap()
}

#[test]
fn test_initialize_success() {
    let (env, contract_id, client) = create_test_env();
    let admin = Address::generate(&env);
    let providers = Some(Map::from_array(
        &env,
        [(Symbol::new(&env, "referrals"), Address::generate(&env))],
    ));

    client.initialize(&admin, &providers);

    env.as_contract(&contract_id, || {
        let stored_admin: Address = env.storage().persistent().get(&DataKey::Admin).unwrap();
        let event_id: u64 = env.storage().persistent().get(&DataKey::EventId).unwrap();
        assert_eq!(stored_admin, admin);
        assert_eq!(event_id, 0);
        let events = env.events().all();
        assert_eq!(
            events.last().unwrap(),
            (
                vec![&env, Symbol::new(&env, "Initialized"), admin.clone()],
                1u32 // Provider count
            )
        );
    });
}

#[test]
fn test_initialize_already_initialized() {
    let (env, _, client) = create_test_env();
    let admin = Address::generate(&env);
    let providers = Some(Map::from_array(
        &env,
        [(Symbol::new(&env, "referrals"), Address::generate(&env))],
    ));

    client.initialize(&admin, &providers);
    let result = client.try_initialize(&admin, &providers);
    assert_eq!(result, Err(Ok(AirdropError::AlreadyInitialized)));
}

#[test]
fn test_trigger_airdrop_success_xlm() {
    let (env, contract_id, client) = create_test_env();
    let admin = Address::generate(&env);
    let (xlm_address, _) = setup_token(&env);

    client.initialize(&admin, &None);

    let conditions = Map::from_array(
        &env,
        [
            (Symbol::new(&env, "referrals"), 5u64),
            (Symbol::new(&env, "subscription_days"), 30u64),
            (Symbol::new(&env, "loyalty_points"), 100u64),
        ],
    );
    let amount = 1000;
    let name = Symbol::new(&env, "Airdrop1");
    let description = Bytes::from_slice(&env, b"Test airdrop");
    let start_time = env.ledger().timestamp();
    let end_time = start_time + 1000;

    client.trigger_airdrop(
        &admin,
        &name,
        &description,
        &conditions,
        &amount,
        &xlm_address,
        &start_time,
        &end_time,
        &None,
        &None,
    );

    env.as_contract(&contract_id, || {
        let event_id: u64 = env.storage().persistent().get(&DataKey::EventId).unwrap();
        assert_eq!(event_id, 1);
        let event: AirdropEvent = env
            .storage()
            .persistent()
            .get(&DataKey::AirdropEvent(1))
            .unwrap();
        assert_eq!(event.conditions, conditions);
        assert_eq!(event.amount, amount);
        assert_eq!(event.token_address, xlm_address);
        let events = env.events().all();
        assert_eq!(
            events.last().unwrap(),
            (
                vec![
                    &env,
                    Symbol::new(&env, "AirdropTriggered"),
                    1u64,
                    admin.clone(),
                    name
                ],
                (env.ledger().timestamp(), amount)
            )
        );
    });
}

#[test]
fn test_trigger_airdrop_success_custom_token() {
    let (env, contract_id, client) = create_test_env();
    let admin = Address::generate(&env);
    let (token_address, _) = setup_token(&env);

    client.initialize(&admin, &None);

    let conditions = Map::from_array(&env, [(Symbol::new(&env, "referrals"), 5u64)]);
    let amount = 500;
    let name = Symbol::new(&env, "Airdrop1");
    let description = Bytes::from_slice(&env, b"Test airdrop");
    let start_time = env.ledger().timestamp();
    let end_time = start_time + 1000;

    client.trigger_airdrop(
        &admin,
        &name,
        &description,
        &conditions,
        &amount,
        &token_address,
        &start_time,
        &end_time,
        &None,
        &None,
    );

    env.as_contract(&contract_id, || {
        let event_id: u64 = env.storage().persistent().get(&DataKey::EventId).unwrap();
        assert_eq!(event_id, 1);
        let event: AirdropEvent = env
            .storage()
            .persistent()
            .get(&DataKey::AirdropEvent(1))
            .unwrap();
        assert_eq!(event.conditions, conditions);
        assert_eq!(event.amount, amount);
        assert_eq!(event.token_address, token_address);
    });
}

#[test]
fn test_trigger_airdrop_invalid_amount() {
    let (env, _, client) = create_test_env();
    let admin = Address::generate(&env);
    let (token_address, _) = setup_token(&env);

    client.initialize(&admin, &None);

    let conditions = Map::new(&env);
    let name = Symbol::new(&env, "Airdrop1");
    let description = Bytes::from_slice(&env, b"Test airdrop");
    let start_time = env.ledger().timestamp();
    let end_time = start_time + 1000;

    let result = client.try_trigger_airdrop(
        &admin,
        &name,
        &description,
        &conditions,
        &0,
        &token_address,
        &start_time,
        &end_time,
        &None,
        &None,
    );
    assert_eq!(result, Err(Ok(AirdropError::InvalidEventConfig)));
}

#[test]
fn test_trigger_airdrop_unauthorized() {
    let (env, contract_id, client) = create_test_env();
    let admin = Address::generate(&env);
    let non_admin = Address::generate(&env);
    let (token_address, _) = setup_token(&env);

    client.initialize(&admin, &None);

    let conditions = Map::from_array(&env, [(Symbol::new(&env, "referrals"), 5u64)]);
    let name = Symbol::new(&env, "Airdrop1");
    let description = Bytes::from_slice(&env, b"Test airdrop");
    let start_time = env.ledger().timestamp();
    let end_time = start_time + 1000;

    env.as_contract(&contract_id, || {
        env.mock_all_auths_with_caller(&non_admin);
        let result = client.try_trigger_airdrop(
            &non_admin,
            &name,
            &description,
            &conditions,
            &1000,
            &token_address,
            &start_time,
            &end_time,
            &None,
            &None,
        );
        assert_eq!(result, Err(Ok(AirdropError::Unauthorized)));
    });
}

#[test]
fn test_claim_airdrop_success() {
    let (env, contract_id, client) = create_test_env();
    let admin = Address::generate(&env);
    let user = Address::generate(&env);
    let (token_address, token_admin) = setup_token(&env);
    let token_client = TokenClient::new(&env, &token_address);

    // Initialize metric providers
    let referral_contract_id = env.register_contract(None, ReferralContract);
    let referral_contract = ReferralContractClient::new(&env, &referral_contract_id);
    referral_contract.initialize(&admin);
    let subscription_contract_id = env.register_contract(None, SubscriptionContract);
    let subscription_contract = SubscriptionContractClient::new(&env, &subscription_contract_id);
    subscription_contract.initialize(&admin);
    let loyalty_contract_id = env.register_contract(None, LoyaltyContract);
    let loyalty_contract = LoyaltyContractClient::new(&env, &loyalty_contract_id);
    loyalty_contract.initialize(&admin);

    // Register providers
    client.register_provider(
        &admin,
        &Symbol::new(&env, "referrals"),
        &referral_contract_id,
    );
    client.register_provider(
        &admin,
        &Symbol::new(&env, "subscription_days"),
        &subscription_contract_id,
    );
    client.register_provider(
        &admin,
        &Symbol::new(&env, "loyalty_points"),
        &loyalty_contract_id,
    );

    // Set user metrics
    referral_contract.record_referral(&admin, &user, &Address::generate(&env));
    subscription_contract.subscribe(&admin, &user);
    env.ledger().with_mut(|l| l.timestamp += 30 * 24 * 60 * 60); // 30 days
    loyalty_contract.add_points(&admin, &user, &100);

    client.initialize(&admin, &None);

    let conditions = Map::from_array(
        &env,
        [
            (Symbol::new(&env, "referrals"), 1u64),
            (Symbol::new(&env, "subscription_days"), 30u64),
            (Symbol::new(&env, "loyalty_points"), 100u64),
        ],
    );
    let amount = 1000;
    let event_id = create_airdrop_event(&client, &admin, conditions, amount, &token_address);

    token_admin.mint(&contract_id, &10000);

    client.claim_airdrop(&user, &event_id);

    assert_eq!(token_client.balance(&user), 1000);
    assert_eq!(token_client.balance(&contract_id), 9000);

    env.as_contract(&contract_id, || {
        let claimed: bool = env
            .storage()
            .persistent()
            .get(&DataKey::Claimed(event_id, user.clone()))
            .unwrap_or(false);
        assert!(claimed);
        let stats: EventStats = env
            .storage()
            .persistent()
            .get(&DataKey::EventStats(event_id))
            .unwrap();
        assert_eq!(stats.recipient_count, 1);
        assert_eq!(stats.total_distributed, 1000);
    });
}

#[test]
fn test_claim_airdrop_not_eligible() {
    let (env, contract_id, client) = create_test_env();
    let admin = Address::generate(&env);
    let user = Address::generate(&env);
    let (token_address, _) = setup_token(&env);

    let referral_contract_id = env.register_contract(None, ReferralContract);
    let referral_contract = ReferralContractClient::new(&env, &referral_contract_id);
    referral_contract.initialize(&admin);
    client.register_provider(
        &admin,
        &Symbol::new(&env, "referrals"),
        &referral_contract_id,
    );

    client.initialize(&admin, &None);

    let conditions = Map::from_array(&env, [(Symbol::new(&env, "referrals"), 5u64)]);
    let amount = 1000;
    let event_id = create_airdrop_event(&client, &admin, conditions, amount, &token_address);

    // User has no referrals
    let result = client.try_claim_airdrop(&user, &event_id);
    assert_eq!(result, Err(Ok(AirdropError::UserNotEligible)));
}

#[test]
fn test_claim_airdrop_already_claimed() {
    let (env, contract_id, client) = create_test_env();
    let admin = Address::generate(&env);
    let user = Address::generate(&env);
    let (token_address, token_admin) = setup_token(&env);

    let referral_contract_id = env.register_contract(None, ReferralContract);
    let referral_contract = ReferralContractClient::new(&env, &referral_contract_id);
    referral_contract.initialize(&admin);
    client.register_provider(
        &admin,
        &Symbol::new(&env, "referrals"),
        &referral_contract_id,
    );

    referral_contract.record_referral(&admin, &user, &Address::generate(&env));

    client.initialize(&admin, &None);

    let conditions = Map::from_array(&env, [(Symbol::new(&env, "referrals"), 1u64)]);
    let amount = 1000;
    let event_id = create_airdrop_event(&client, &admin, conditions, amount, &token_address);

    token_admin.mint(&contract_id, &10000);

    client.claim_airdrop(&user, &event_id);

    let result = client.try_claim_airdrop(&user, &event_id);
    assert_eq!(result, Err(Ok(AirdropError::AlreadyClaimed)));
}

#[test]
fn test_claim_airdrop_invalid_event() {
    let (env, _, client) = create_test_env();
    let admin = Address::generate(&env);
    let user = Address::generate(&env);

    client.initialize(&admin, &None);

    let result = client.try_claim_airdrop(&user, &1);
    assert_eq!(result, Err(Ok(AirdropError::AirdropNotFound)));
}

#[test]
fn test_claim_airdrop_unauthenticated() {
    let (env, contract_id, client) = create_test_env();
    let admin = Address::generate(&env);
    let user = Address::generate(&env);
    let (token_address, token_admin) = setup_token(&env);

    let referral_contract_id = env.register_contract(None, ReferralContract);
    let referral_contract = ReferralContractClient::new(&env, &referral_contract_id);
    referral_contract.initialize(&admin);
    client.register_provider(
        &admin,
        &Symbol::new(&env, "referrals"),
        &referral_contract_id,
    );

    referral_contract.record_referral(&admin, &user, &Address::generate(&env));

    client.initialize(&admin, &None);

    let conditions = Map::from_array(&env, [(Symbol::new(&env, "referrals"), 1u64)]);
    let amount = 1000;
    let event_id = create_airdrop_event(&client, &admin, conditions, amount, &token_address);

    token_admin.mint(&contract_id, &10000);

    env.as_contract(&contract_id, || {
        env.mock_all_auths_with_caller(&user);
        env.auths().pop(); // Remove auth for user
        let result = client.try_claim_airdrop(&user, &event_id);
        assert_eq!(
            result,
            Err(Err(soroban_sdk::Error::from_type_and_code(
                soroban_sdk::xdr::ScErrorType::Auth,
                soroban_sdk::xdr::ScErrorCode::InvalidAction
            )))
        );
    });
}

#[test]
fn test_distribute_all_success() {
    let (env, contract_id, client) = create_test_env();
    let admin = Address::generate(&env);
    let (token_address, token_admin) = setup_token(&env);
    let token_client = TokenClient::new(&env, &token_address);

    let referral_contract_id = env.register_contract(None, ReferralContract);
    let referral_contract = ReferralContractClient::new(&env, &referral_contract_id);
    referral_contract.initialize(&admin);
    client.register_provider(
        &admin,
        &Symbol::new(&env, "referrals"),
        &referral_contract_id,
    );

    let users: Vec<Address> = (0..10).map(|_| Address::generate(&env)).collect::<Vec<_>>();

    client.initialize(&admin, &None);

    let conditions = Map::from_array(&env, [(Symbol::new(&env, "referrals"), 1u64)]);
    let amount = 1000;
    let event_id = create_airdrop_event(&client, &admin, conditions, amount, &token_address);

    for i in 0..10 {
        let user = &users[i];
        if i < 6 {
            referral_contract.record_referral(&admin, user, &Address::generate(&env));
        }
    }

    token_admin.mint(&contract_id, &10000);

    client.distribute_all(&admin, &event_id, &users);

    env.as_contract(&contract_id, || {
        let stats: EventStats = env
            .storage()
            .persistent()
            .get(&DataKey::EventStats(event_id))
            .unwrap();
        assert_eq!(stats.recipient_count, 6);
        assert_eq!(stats.total_distributed, 6000);
        for i in 0..10 {
            let user = &users[i];
            let claimed: bool = env
                .storage()
                .persistent()
                .get(&DataKey::Claimed(event_id, user.clone()))
                .unwrap_or(false);
            if i < 6 {
                assert_eq!(token_client.balance(user), 1000);
                assert!(claimed);
            } else {
                assert_eq!(token_client.balance(user), 0);
                assert!(!claimed);
            }
        }
    });

    assert_eq!(token_client.balance(&contract_id), 4000);
}

#[test]
fn test_distribute_all_unauthorized() {
    let (env, contract_id, client) = create_test_env();
    let admin = Address::generate(&env);
    let non_admin = Address::generate(&env);
    let (token_address, _) = setup_token(&env);

    client.initialize(&admin, &None);

    let conditions = Map::from_array(&env, [(Symbol::new(&env, "referrals"), 1u64)]);
    let amount = 1000;
    let event_id = create_airdrop_event(&client, &admin, conditions, amount, &token_address);

    env.as_contract(&contract_id, || {
        env.mock_all_auths_with_caller(&non_admin);
        let result = client.try_distribute_all(&non_admin, &event_id, &Vec::new(&env));
        assert_eq!(result, Err(Ok(AirdropError::Unauthorized)));
    });
}

#[test]
fn test_check_eligibility_success() {
    let (env, contract_id, client) = create_test_env();
    let admin = Address::generate(&env);
    let user = Address::generate(&env);
    let (token_address, _) = setup_token(&env);

    let referral_contract_id = env.register_contract(None, ReferralContract);
    let referral_contract = ReferralContractClient::new(&env, &referral_contract_id);
    referral_contract.initialize(&admin);
    client.register_provider(
        &admin,
        &Symbol::new(&env, "referrals"),
        &referral_contract_id,
    );

    referral_contract.record_referral(&admin, &user, &Address::generate(&env));

    client.initialize(&admin, &None);

    let conditions = Map::from_array(&env, [(Symbol::new(&env, "referrals"), 1u64)]);
    let amount = 1000;
    let event_id = create_airdrop_event(&client, &admin, conditions, amount, &token_address);

    env.as_contract(&contract_id, || {
        let provider: Address = env
            .storage()
            .persistent()
            .get(&DataKey::ProviderRegistry(Symbol::new(&env, "referrals")))
            .unwrap();
        let referral_client = ReferralContractClient::new(&env, &provider);
        let metric = Symbol::new(&env, "referrals");
        let result = referral_client.get_user_metric(&user, &metric);
        assert_eq!(result, Ok(1));
    });
}

#[test]
fn test_check_eligibility_not_eligible() {
    let (env, contract_id, client) = create_test_env();
    let admin = Address::generate(&env);
    let user = Address::generate(&env);
    let (token_address, _) = setup_token(&env);

    let referral_contract_id = env.register_contract(None, ReferralContract);
    let referral_contract = ReferralContractClient::new(&env, &referral_contract_id);
    referral_contract.initialize(&admin);
    client.register_provider(
        &admin,
        &Symbol::new(&env, "referrals"),
        &referral_contract_id,
    );

    client.initialize(&admin, &None);

    let conditions = Map::from_array(&env, [(Symbol::new(&env, "referrals"), 5u64)]);
    let amount = 1000;
    let event_id = create_airdrop_event(&client, &admin, conditions, amount, &token_address);

    env.as_contract(&contract_id, || {
        let provider: Address = env
            .storage()
            .persistent()
            .get(&DataKey::ProviderRegistry(Symbol::new(&env, "referrals")))
            .unwrap();
        let referral_client = ReferralContractClient::new(&env, &provider);
        let metric = Symbol::new(&env, "referrals");
        let result = referral_client.get_user_metric(&user, &metric);
        assert_eq!(result, Ok(0)); // No referrals
    });
}

#[test]
fn test_insufficient_contract_balance() {
    let (env, contract_id, client) = create_test_env();
    let admin = Address::generate(&env);
    let user = Address::generate(&env);
    let (token_address, _) = setup_token(&env);

    let referral_contract_id = env.register_contract(None, ReferralContract);
    let referral_contract = ReferralContractClient::new(&env, &referral_contract_id);
    referral_contract.initialize(&admin);
    client.register_provider(
        &admin,
        &Symbol::new(&env, "referrals"),
        &referral_contract_id,
    );

    referral_contract.record_referral(&admin, &user, &Address::generate(&env));

    client.initialize(&admin, &None);

    let conditions = Map::from_array(&env, [(Symbol::new(&env, "referrals"), 1u64)]);
    let amount = 1000;
    let event_id = create_airdrop_event(&client, &admin, conditions, amount, &token_address);

    let result = client.try_claim_airdrop(&user, &event_id);
    assert_eq!(result, Err(Ok(AirdropError::InsufficientContractBalance)));
}
