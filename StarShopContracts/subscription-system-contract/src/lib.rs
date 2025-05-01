#![no_std]

use soroban_sdk::{contract, contractimpl, Address, Bytes, Env, String, Symbol};

mod access;
mod expiration;
mod minting;
mod plans;

use crate::access::{
    access_gold_feature, add_role, admin_reset_subscription, get_usage_count, view_premium_content,
};
use crate::expiration::{
    cleanup_expired, get_subscription_state, is_in_grace_period, SubscriptionState,
};
use crate::minting::{is_active, is_expired, mint_subscription, renew_subscription};
use crate::plans::{create_plan, disable_plan, get_plan, update_plan, Plan};

#[contract]
pub struct SubscriptionContract;

#[contractimpl]
impl SubscriptionContract {
    // -----------------------
    // 📦 PLAN MANAGEMENT
    // -----------------------

    pub fn create_plan(
        env: Env,
        admin: Address,
        plan_id: Symbol,
        name: Bytes,
        duration: u64,
        price: u64,
        benefits: Bytes,
        version: u32,
        tier: Symbol,
    ) {
        create_plan(
            &env, admin, plan_id, name, duration, price, benefits, version, tier,
        );
    }

    pub fn update_plan(
        env: Env,
        admin: Address,
        plan_id: Symbol,
        name: Bytes,
        duration: u64,
        price: u64,
        benefits: Bytes,
        version: u32,
        tier: Symbol,
    ) {
        update_plan(
            &env, admin, plan_id, name, duration, price, benefits, version, tier,
        );
    }

    pub fn disable_plan(env: Env, admin: Address, plan_id: Symbol) {
        disable_plan(&env, admin, plan_id);
    }

    pub fn get_plan(env: Env, plan_id: Symbol) -> Option<Plan> {
        get_plan(&env, plan_id)
    }

    // -----------------------
    // 🪙 SUBSCRIPTION MINTING
    // -----------------------

    pub fn subscribe(env: Env, user: Address, plan_id: Symbol) {
        mint_subscription(&env, user, plan_id);
    }

    pub fn renew(env: Env, user: Address, plan_id: Symbol) {
        renew_subscription(&env, user, plan_id);
    }

    // -----------------------
    // 🔐 ACCESS VERIFICATION
    // -----------------------

    pub fn is_active_sub(env: Env, user: Address, plan_id: Symbol) -> bool {
        is_active(&env, user, plan_id)
    }

    pub fn is_expired_sub(env: Env, user: Address, plan_id: Symbol) -> bool {
        is_expired(&env, user, plan_id)
    }

    pub fn is_in_grace(env: Env, user: Address, plan_id: Symbol) -> bool {
        is_in_grace_period(&env, user, plan_id)
    }

    pub fn get_state(env: Env, user: Address, plan_id: Symbol) -> SubscriptionState {
        get_subscription_state(&env, user, plan_id)
    }

    // -----------------------
    // 🎯 FEATURE ACCESS
    // -----------------------

    pub fn premium_content(env: Env, user: Address, plan_id: Symbol) -> String {
        view_premium_content(&env, user, plan_id)
    }

    pub fn gold_feature(env: Env, user: Address, plan_id: Symbol) -> Symbol {
        access_gold_feature(&env, user, plan_id)
    }

    // -----------------------
    // 🔧 ADMIN/ROLE MANAGEMENT
    // -----------------------

    pub fn add_user_role(env: Env, role: Symbol, user: Address) {
        add_role(&env, role, user);
    }

    pub fn reset_subscription(env: Env, admin: Address, target_user: Address, plan_id: Symbol) {
        admin_reset_subscription(&env, admin, target_user, plan_id);
    }

    pub fn get_feature_usage(env: Env, user: Address, feature: Symbol) -> u32 {
        get_usage_count(&env, user, feature)
    }

    // -----------------------
    // 🧹 EXPIRATION CLEANUP
    // -----------------------

    pub fn cleanup(env: Env, user: Address, plan_id: Symbol) -> bool {
        cleanup_expired(&env, user, plan_id)
    }
}
